use wx_dump::{config, db_decrypt, media_decrypt, sys};

use anyhow::Result;
use cliclack::{intro, log, note, outro};
use console::style;
use tabled::{
    settings::{object::Columns, style::Style, Color, Modify},
    Table, Tabled,
};

#[derive(Tabled)]
struct EnvSummary {
    #[tabled(rename = "Property")]
    key: String,
    #[tabled(rename = "Value")]
    value: String,
}

const BANNER: &str = r#"
               .:-=++***++=-:.
           :=*%@@@@@@@@@@@@@@@%*=.
        :+%@@@@@@@@@@@@@@@@@@@@@@@%=.
      :#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@*.
     *@@@@@@@@@%%@@@@@@@@@@@%%@@@@@@@@@=
    %@@@@@@@@#++++%@@@@@@@#++++%@@@@@@@@+
   #@@@@@@@@@#++++%@@@@@@@#++++%@@@@@@@@@=
  :@@@@@@@@@@@@%%@@@@@@@@@@@%%@@@%#*++====.
  =@@@@@@@@@@@@@@@@@@@@@@@@@@@*=-=+*##%%%%@%%#*=:.
  -@@@@@@@@@@@@@@@@@@@@@@@@#-:=#@@@@@@@@@@@@@@@@@@#-.
   %@@@@@@@@@@@@@@@@@@@@@%::*@@@@@@@@@@@@@@@@@@@@@@@@+
   :@@@@@@@@@@@@@@@@@@@@* +@@@@@@@%#%@@@@@@@@%#%@@@@@@%:
    :%@@@@@@@@@@@@@@@@@* *@@@@@@@*===%@@@@@@*===%@@@@@@@-
      +@@@@@@@@@@@@@@@@.-@@@@@@@@%#*#@@@@@@@%#*#@@@@@@@@@
       .+%@@@@@@@@@@@@# #@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@:
         .@@@@@@@@@@@@% *@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@:
         *@@@#==+**#%%%::@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#
         #*-.            =@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%.
                          :%@@@@@@@@@@@@@@@@@@@@@@@@@@+
                            =#@@@@@@@@@@@@@@@@@@@@@@*:
                              :=#@@@@@@@@@@@@@@@@@@:
                                  :-=+*****++=-=*@@#
                                                  :-
      -+=+++=-.   -++-   =++. =++:     -++- :+++++=-.
      #@@@%%@@@#: *@@#   @@@- @@@@-   =@@@* +@@@##@@@*
      #@@=   =@@@ +@@*   %@@- %@@@@+ *@@@@* =@@#  =@@@
      #@@=   =@@@ +@@#   @@@: %@@+@@@@%+@@* =@@@@@@@%-
      #@@@%%@@@#: .#@@%#@@@*  @@@..%@* -@@# +@@%::..
      -++++++-.     :+*#*=:   =++.     :++- :++=
"#;

fn main() -> Result<()> {
    println!("{}", style(BANNER).cyan().bold());
    intro(
        style(" WeChat Database & Media Decryptor ")
            .on_cyan()
            .black(),
    )?;

    sys::check_arch()?;

    log::step(style("Starting environment detection...").bold().yellow())?;
    let pid = unsafe { sys::find_wechat_pid()? };
    let data_dir = config::find_wechat_data_dir()?;
    let uids = config::find_user_unique_ids()?;
    
    // Initial user detection
    let mut current_wxid = match config::parse_global_config(&data_dir) {
        Ok(info) => info.wxid,
        Err(_) => {
            log::step(style("Could not auto-detect wxid from global_config.").yellow())?;
            "".to_string()
        }
    };

    loop {
        if current_wxid.is_empty() {
            let accounts = config::list_accounts(&data_dir)?;
            if accounts.is_empty() {
                anyhow::bail!("No WeChat account directories found in {:?}", data_dir);
            }
            
            let mut select = cliclack::select("Multiple accounts found or auto-detection failed. Please select an account:");
            for acc in &accounts {
                select = select.item(acc, acc, "");
            }
            current_wxid = select.interact()?.to_string();
        }

        let mut wxid_dir = None;
        for entry in std::fs::read_dir(&data_dir)? {
            let entry = entry?;
            let folder_name = entry.file_name().to_string_lossy().to_string();
            if folder_name.starts_with(&format!("{}_", current_wxid)) || folder_name == current_wxid {
                wxid_dir = Some(entry.path());
                break;
            }
        }

        let wxid_dir = match wxid_dir {
            Some(dir) => dir,
            None => {
                log::step(style(format!("Failed to find data folder for wxid: {}", current_wxid)).red())?;
                current_wxid = "".to_string();
                continue;
            }
        };

        let db_storage = wxid_dir.join("db_storage");
        if !db_storage.exists() {
            log::step(style(format!("Database storage directory not found for {}: {:?}", current_wxid, db_storage)).red())?;
            current_wxid = "".to_string();
            continue;
        }

        log::step(style(format!("Selected account: {}", current_wxid)).green().bold())?;

        let uids_str = uids.join(", ");
        let output_dir = std::env::current_dir()?.join("output").join(&current_wxid);
        if !output_dir.exists() {
            std::fs::create_dir_all(&output_dir)?;
        }

        // Try to get more info if possible (optional)
        let (nickname, avatar_url) = match config::parse_global_config(&data_dir) {
            Ok(info) if info.wxid == current_wxid => (info.nickname, info.avatar_url),
            _ => ("Unknown".to_string(), "".to_string()),
        };

        let account_json_path = output_dir.join("account.json");
        let account_data = serde_json::json!({
            "nick": nickname,
            "username": current_wxid,
            "avatar_url": avatar_url
        });

        std::fs::write(
            &account_json_path,
            serde_json::to_string_pretty(&account_data)?
        )?;
        log::step(style(format!("Account info saved to {:?}", account_json_path)).green())?;

        let data = vec![
            EnvSummary {
                key: "Process PID".to_string(),
                value: pid.to_string(),
            },
            EnvSummary {
                key: "Data Directory".to_string(),
                value: data_dir.display().to_string(),
            },
            EnvSummary {
                key: "User UIDs".to_string(),
                value: uids_str,
            },
            EnvSummary {
                key: "Nickname".to_string(),
                value: nickname,
            },
            EnvSummary {
                key: "Database Path".to_string(),
                value: db_storage.display().to_string(),
            },
        ];

        let mut table = Table::new(data);
        table
            .with(Style::modern())
            .with(Modify::new(Columns::first()).with(Color::FG_CYAN));

        note("Environment Detection Results", table.to_string())?;

        log::step(style("Entering core decryption phase...").bold().yellow())?;

        match db_decrypt::dump_and_decrypt(pid, &db_storage, &current_wxid)? {
            db_decrypt::DecryptResult::Success => {
                media_decrypt::decrypt_media(&wxid_dir, &current_wxid, &uids)?;
                break;
            }
            db_decrypt::DecryptResult::NoKeysFound => {
                log::step(style(format!("No decryption keys found for account: {}", current_wxid)).red().bold())?;
                let choice = cliclack::select("Would you like to try another account?")
                    .item(true, "Select another account", "")
                    .item(false, "Exit", "")
                    .interact()?;
                
                if choice {
                    current_wxid = "".to_string();
                    continue;
                } else {
                    anyhow::bail!("No matching database keys found in memory. Ensure WeChat is logged in!");
                }
            }
        }
    }

    outro(style("All tasks completed successfully!").green().bold())?;

    Ok(())
}
