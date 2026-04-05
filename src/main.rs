mod config;
mod db_decrypt;
mod media_decrypt;
mod sys;

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
    let user_info = config::parse_global_config(&data_dir)?;
    let wxid = user_info.wxid;
    let nickname = user_info.nickname;

    let mut wxid_dir = None;
    for entry in std::fs::read_dir(&data_dir)? {
        let entry = entry?;
        let folder_name = entry.file_name().to_string_lossy().to_string();
        if folder_name.starts_with(&format!("{}_", wxid)) || folder_name == wxid {
            wxid_dir = Some(entry.path());
            break;
        }
    }

    let wxid_dir = match wxid_dir {
        Some(dir) => dir,
        None => anyhow::bail!("Failed to find data folder for wxid: {}", wxid),
    };

    let db_storage = wxid_dir.join("db_storage");
    if !db_storage.exists() {
        anyhow::bail!("Database storage directory not found: {:?}", db_storage);
    }

    let uids_str = uids.join(", ");

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

    db_decrypt::dump_and_decrypt(pid, &db_storage, &wxid)?;

    media_decrypt::decrypt_media(&wxid_dir, &wxid, &uids)?;

    outro(style("All tasks completed successfully!").green().bold())?;

    Ok(())
}
