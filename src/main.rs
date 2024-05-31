use argh::FromArgs;
use goblin::pe::{section_table::SectionTable, PE};
use indicatif::{HumanBytes, ProgressBar, ProgressStyle};
use std::{io::{stdout, Write}, path::PathBuf, process::ExitCode};


/// Utility for locating potential code caves in x64 PE files.
#[derive(FromArgs, PartialEq, Debug)]
struct Cli {
    /// executable file to scan
    #[argh(positional)]
    input: PathBuf,
    /// output list file, set empty for stdout
    #[argh(option, short = 'o')]
    output: Option<PathBuf>,
    /// minimal cave size to consider (in bytes)
    #[argh(option, short = 'm')]
    min_size: u64,
}


fn main() -> ExitCode {
    let cli = argh::from_env::<Cli>();
    match main_internal(&cli).is_ok() {
        true => ExitCode::SUCCESS,
        false => ExitCode::FAILURE,
    }
}

fn main_internal(cli: &Cli) -> Result<(), anyhow::Error> {
    con::info_kv("selected executable", cli.input.to_string_lossy());
    con::info_kv("selected minimal size", HumanBytes(cli.min_size));

    let buffer = std::fs::read(&cli.input)
        .inspect(|buf| con::info_kv("read executable", HumanBytes(buf.len() as u64)))
        .inspect_err(|err| con::error_kv("failed to read executable", err))?;

    let executable = PE::parse(&buffer)
        .inspect(|exe| con::info_kv("parsed executable", exe.name.unwrap_or("???")))
        .inspect_err(|err| con::error_kv("failed to parse executable", err))
        .map_err(|err| anyhow::anyhow!(err))?;

    if !executable.is_64 {
        con::error_kv("unsupported architecture", "32-bit");
        anyhow::bail!("unsupported architecture");
    }

    let section = find_text_section(&executable)
        .inspect(|&sec| con::info_kv("found .text",
            format!("pointer to raw data = 0x{:X}", sec.pointer_to_raw_data)))
        .inspect_err(|_| con::info("failed to find .text"))?;

    let text = {
        let offset = section.pointer_to_raw_data as usize;
        let size = section.size_of_raw_data as usize;
        buffer.get(offset .. offset + size).ok_or_else(|| anyhow::anyhow!("range out of bounds"))
    }
        .inspect_err(|err| con::error_kv("failed to get .text", err))?;

    // std::fs::write("./dbg-text.bin", text)?;

    let progress_style = ProgressStyle::with_template(
        "[{percent_precise}%] {bar:40.cyan/cyan} {pos:>7}/{len:7} {msg}"
    )?.progress_chars("##-");
    let progress_bar = ProgressBar::new(text.len() as u64).with_style(progress_style);

    con::info_kv("scanning .text for int3 sequences",
        format!("size of raw data = {}", HumanBytes(section.size_of_raw_data as u64)));

    let mut matches_cc = Vec::new();

    let mut i = 0_usize;
    while i < text.len() {
        let mut byte = unsafe { *text.get_unchecked(i) };
        let start_pos = i;

        match byte {
            0xCC => {
                while byte == 0xCC && i < text.len() {
                    byte = unsafe { *text.get_unchecked(i) };
                    i += 1;
                }

                let length = (i - start_pos) as u64;
                progress_bar.inc(length);

                if length >= cli.min_size {
                    matches_cc.push((start_pos, length));
                }
            },
            _ => {
                progress_bar.inc(1);
                i += 1;
            }
        }
    }

    progress_bar.finish_and_clear();
    con::info_kv("scan completed", format!("{} match(es) on 0xcc", matches_cc.len()));

    let write_digest = |mut output: Box<dyn Write>| {
        for (i, (start, length)) in matches_cc.iter().cloned().enumerate() {
            // Currently `start` has offset form .exe start, but what we need is the rva.
            let rva = start + section.virtual_address as usize;
            writeln!(*output, "{}. at 0x{:x} length = {}", i, rva, length)?;
        }
        Ok::<(), anyhow::Error>(())
    };

    match &cli.output {
        Some(path) => write_digest(Box::new(std::fs::File::create(path)?))?,
        None => write_digest(Box::new(stdout()))?,
    };

    Ok(())
}

fn find_text_section<'a>(executable: &'a PE) -> anyhow::Result<&'a SectionTable> {
    for section in &executable.sections {
        if section.name().ok().is_some_and(|name| name == ".text") {
            return Ok(section);
        }
    }

    anyhow::bail!("failed to find .text")
}


#[allow(dead_code)]
mod con {
    use console::style;
    use std::fmt;

    pub fn info(value: impl fmt::Display) {
        println!("{}", style(value).cyan());
    }

    pub fn info_kv(key: &str, value: impl fmt::Display) {
        println!("{} {}", style(key).cyan(), value);
    }

    pub fn error(value: impl fmt::Display) {
        println!("{}", style(value).red().bold());
    }

    pub fn error_kv(key: &str, value: impl fmt::Display) {
        eprintln!("{} {}", style(key).red().bold(), value.to_string().to_lowercase());
    }
}
