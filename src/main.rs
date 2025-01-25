use clap::{Parser, Subcommand};
use rand::distributions::Uniform;
use rand::{thread_rng, Rng};
use copypasta::{ClipboardContext, ClipboardProvider};
use std::io::{self, Write};
use crossterm::event::{read, Event, KeyCode};
use crossterm::execute;
use crossterm::style::{Attribute, Color, Print, ResetColor, SetAttribute, SetForegroundColor};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use passwords::analyzer;
use passwords::scorer;

use std:: {
    fs::{self, OpenOptions},
    iter,
    path::Path,
};

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Subcommand)]
enum Commands{
    List, 
    Add {
        #[arg(short, long)]
        service: String,
        #[arg(short, long)]
        username: String,
        #[arg(short, long, default_missing_value("true"))]
        clipboard: bool,
        #[arg(short, long, default_missing_value("true"))]
        generate: bool,
        #[arg(short, long, default_missing_value("true"))]
        write: bool,
    }
}

#[derive(PartialEq)]
enum WeakPasswordChoice {
    ABORT,
    CONTINUE,
}
fn main() -> std::io::Result<()> {
    let args = Cli::parse();
    match args.cmd {
        Commands::List => display_passwords(),
        Commands::Add{
            service,
            username,
            clipboard,
            generate,
            write,
        } => {
            println!("{}, {}, clipboard: {}, generate: {}, write: {}",
                service, username, clipboard, generate, write
            );
            if generate {
                let password: String = generate_password();
                println!("{}", password);
                let _ = add_new_password(&service, &username, &password);
            }
            if clipboard {
                let password = get_clipboard_password();
                println!("{}", password);
                if should_save_password(&password) {
                    let _ = add_new_password(&service, &username, &password);
                }
            }

            if write {
                let password = get_user_input().unwrap();
                println!("You typed: {}", password);
                if should_save_password(&password) {
                    let _ = add_new_password(&service, &username, &password);
                }
            }
        }
    }
    Ok(())
}

fn display_passwords() {
    println!("Listed Passwords are: ");
    let path = Path::new("passwords.txt");
    let contents = fs::read_to_string(path).expect("Could not read the password file");
    println!("{}", contents);
}

fn add_new_password(service: &str, username: &str, password: &str) -> std::io::Result<()> {
    let path = Path::new("passwords.txt");
    let password_infos = format!("{}|{}|{}\n", service, username, password);
    let mut file = OpenOptions::new().append(true).open(path)?;
    file.write_all(password_infos.as_bytes())?;
    Ok(())
}

fn generate_password() -> String {
    let charset: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                           abcdefghijklmnopqrstuvwxyz\
                           0123456789\
                           !@#$%^&*()_-+=[{]}\\;:'\",<.>/?";
    let mut rng = thread_rng();
    let password: String = iter::repeat_with(|| {
        let idx = rng.sample(Uniform::from(0..charset.len()));
        charset[idx] as char
    })
    .take(16)
    .collect();
    password
}

fn get_clipboard_password() -> String {
    let mut ctx = ClipboardContext::new().unwrap();
    return ctx.get_contents().unwrap()
}

fn get_user_input() -> io::Result<String> {
    println!("Write it down the press Enter!");
    let mut input = String::new();
    match io::stdin().read_line(&mut input){
        Ok(_n) => return Ok(input.trim().to_string()),
        Err(error) => Err(error),
    }
}

fn should_save_password(password: &str) -> bool {
    if is_password_weak(password) {
        print_alert(password);
        if let Ok(choice) = read_next_char() {
            return choice == WeakPasswordChoice::CONTINUE;
        } else {
            return false;
        }
    } else {
        return true;
    }
}

fn is_password_weak(password: &str) -> bool {
    let score = scorer::score(&analyzer::analyze(password));
    return score < 80.0;
}

fn print_alert(password: &str) {
    let alert = format!(
        "{} is a weak password. Press Enter to coninue anyway. Press Q to abort and try again!",
        password
    );
    execute!(
        io::stdout(),
        SetForegroundColor(Color::Red),
        SetAttribute(Attribute::Bold),
        Print(alert),
        ResetColor,
        SetAttribute(Attribute::Reset)
    )
    .unwrap();
}

fn read_next_char() -> io::Result<WeakPasswordChoice> {
    enable_raw_mode()?;
    let result = loop {
        match read()? {
            Event::Key(event) => {
                match event.code  {
                    KeyCode::Char('q') | KeyCode::Char('Q') => {
                        break Ok(WeakPasswordChoice::ABORT);
                    }
                    KeyCode::Enter => {
                        break Ok(WeakPasswordChoice::CONTINUE);
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    };
    disable_raw_mode()?;
    result
}