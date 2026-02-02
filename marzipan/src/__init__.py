# from rich.console import Console
import click

from .parser import *
from .util import export, pkgs, rename, setup_exports

target_subdir = "target/proverif"

(__all__, export) = setup_exports()
export(setup_exports)


console = pkgs.rich.console.Console()
logger = pkgs.logging.getLogger(__name__)


def set_logging_logrecordfactory(filename):
    old_factory = pkgs.logging.getLogRecordFactory()

    def record_factory(*args, **kwargs):
        record = old_factory(*args, **kwargs)
        record.filename = filename
        return record

    pkgs.logging.setLogRecordFactory(record_factory)


# def set_logging_format(max_length):
#    pass
#    #format_str = "{levelname:<8} {filename:<" + str(max_length + 2) + "} {message}"
#    #pkgs.logging.basicConfig(level=pkgs.logging.DEBUG, style="{", format=format_str)


@click.group()
def main():
    pkgs.logging.basicConfig(level=pkgs.logging.DEBUG)


def eprint(*args, **kwargs):
    print(*args, **{"file": pkgs.sys.stderr, **kwargs})


def exc(argv, **kwargs):
    eprint("$", *argv)
    command = pkgs.subprocess.run(argv, **kwargs)

    if command.returncode != 0:
        logger.error("subprocess with terminated with non-zero return code.")
        eprint("", *argv)
        exit(command.returncode)

    if command.stdout is not None:
        return command.stdout.decode("utf-8")

    return ""


def exc_piped(argv, **kwargs):
    eprint("$", *argv)
    return pkgs.subprocess.Popen(argv, **kwargs)


def clean_line(prev_line, line):
    line = line.rstrip()
    if pkgs.re.match(r"^Warning: identifier \w+ rebound.$", line) or prev_line is None:
        return None
    return prev_line


def run_proverif(file, log_file, extra_args=[]):
    params = ["proverif", "-test", *extra_args, file]
    logger.debug(params)

    process = exc_piped(
        params,
        stderr=pkgs.subprocess.PIPE,
        stdout=pkgs.subprocess.PIPE,
        text=True,
        bufsize=1,
    )
    try:
        prev_line = None
        with open(log_file, "a") as log:
            for line in process.stdout:
                log.write(line)
                cleaned_line = clean_line(prev_line, line)
                prev_line = line
                if cleaned_line is not None:
                    yield cleaned_line
            if prev_line is not None:
                yield prev_line

    except Exception as e:
        # When does this happen? Should the error even be ignored? Metaverif should probably just abort here, right? --karo
        logger.error(f"Proverif generated an exception with {params}: {e}")
        exit(1)
    finally:
        process.stdout.close()
        return_code = process.wait()

        if return_code != 0:
            logger.error(
                f"Proverif exited with a non-zero error code {params}: {return_code}"
            )
            if prev_line is not None:
                logger.error(f"Last line of log file {log_file}:")
                logger.error(f"> {prev_line.rstrip()}")
            exit(return_code)


def m4(input_file, output_file):
    logger.debug(f"m4: {input_file}, {output_file}")
    input_file_path = pkgs.pathlib.Path(input_file)

    params = ["m4", "-D", "ProVerif", pkgs.os.path.basename(input_file)]
    return exc(
        params, stderr=pkgs.sys.stderr, cwd=input_file_path.parent, stdout=output_file
    )


def cpp(file, cpp_prep):
    logger.debug(f"_cpp: {file}, {cpp_prep}")
    file_path = pkgs.pathlib.Path(file)

    dirname = file_path.parent
    cwd = pkgs.pathlib.Path.cwd()

    params = ["cpp", "-P", f"-I{dirname}", file, "-o", cpp_prep]
    return exc(params, stderr=pkgs.sys.stderr)


def awk(repo_path, cpp_prep, awk_prep):
    params = [
        "awk",
        "-f",
        str(pkgs.os.path.join(repo_path, "marzipan/marzipan.awk")),
        cpp_prep,
    ]
    with open(awk_prep, "w") as file:
        exc(params, stderr=pkgs.sys.stderr, stdout=file)
        file.write("\nprocess main")


def pretty_output_line(prefix, mark, color, text):
    content = f"{mark} {text}"
    console.print(prefix, style="grey42", end="", no_wrap=True)
    console.print(content, style=color)


def pretty_output_init(file_path):
    expected = []
    descs = []

    with open(file_path, "r") as file:
        content = file.read()

        # Process lemmas first
        result = pkgs.re.findall(r"@(lemma)(?=\s+\"([^\"]*)\")", content)
        if result:
            # The regex only returns lemmas. For lemmas, we always expect the result 'true' from ProVerif.
            expected.extend([True for _ in range(len(result))])
            descs.extend([e[1] for e in result])

        # Then process regular queries
        result = pkgs.re.findall(r'@(query|reachable)(?=\s+"[^\"]*")', content)
        if result:
            # For queries, we expect 'true' from ProVerif, for reachable, we expect 'false'.
            expected.extend([e == "@query" for e in result])
            reachable_result = pkgs.re.findall(
                r'@(query|reachable)\s+"([^\"]*)"', content
            )
            descs.extend([e[1] for e in reachable_result])

    ta = pkgs.time.time()
    res = 0
    ctr = 0
    return (ta, res, ctr, expected, descs)


def pretty_output_step(file_path, line, expected, descs, res, ctr, ta):
    tz = pkgs.time.time()

    # Output from ProVerif contains a trailing newline, which we do not have in the expected output. Remove it for meaningful matching.
    outp_clean_raw = line.rstrip()
    if outp_clean_raw == "true":
        outp_clean = True
    elif outp_clean_raw == "false":
        outp_clean = False
    else:
        outp_clean = outp_clean_raw

    if outp_clean == expected[ctr]:
        pretty_output_line(f"{int(tz - ta)}s ", "✔", "green", descs[ctr])
    else:
        res = 1
        pretty_output_line(f"{int(tz - ta)}s ", "✖", "red", descs[ctr])

    ctr += 1
    ta = tz

    return (res, ctr, ta)


def pretty_output(file_path):
    (ta, res, ctr, expected, descs) = pretty_output_init(file_path)
    for line in pkgs.sys.stdin:
        (res, ctr, ta) = pretty_output_step(
            file_path, line, expected, descs, res, ctr, ta
        )


def get_target_dir(path, output):
    if output is not None and not output == "":
        return pkgs.pathlib.Path(output)
    else:
        return pkgs.os.path.join(path, target_subdir)


@main.command()
@click.option("--output", "output", required=False)
@click.argument("repo_path")
def analyze(repo_path, output):
    target_dir = get_target_dir(repo_path, output)
    pkgs.os.makedirs(target_dir, exist_ok=True)

    entries = []
    analysis_dir = pkgs.os.path.join(repo_path, "analysis")
    full_paths = sorted(pkgs.glob.glob(str(analysis_dir) + "/*.entry.mpv"))
    entries.extend(full_paths)

    # modelnames = [pkgs.os.path.basename(path).replace('.entry.mpv', '') for path in full_paths]
    # max_length = max(len(modelname) for modelname in modelnames) if modelnames else 0
    # set_logging_format(max_length)

    with pkgs.concurrent.futures.ProcessPoolExecutor() as executor:
        futures = {
            executor.submit(metaverif, repo_path, target_dir, entry): entry
            for entry in entries
        }
        for future in pkgs.concurrent.futures.as_completed(futures):
            cmd = futures[future]
            logger.info(f"Metaverif {cmd} finished.")

    print("all processes finished.")


@main.command()
@click.option("--output", "output", required=False)
@click.argument("repo_path")
def clean(repo_path, output):
    cleans_failed = 0
    target_dir = get_target_dir(repo_path, output)
    if pkgs.os.path.isdir(target_dir):
        for filename in pkgs.os.listdir(target_dir):
            file_path = pkgs.os.path.join(target_dir, filename)
            if pkgs.os.path.isfile(file_path) and pkgs.os.path.splitext(file_path)[
                1
            ] in [".pv", ".log"]:
                try:
                    pkgs.os.remove(file_path)
                except Exception as e:
                    print(f"Error deleting {file_path}: {str(e)}")
                    cleans_failed += 1

    if cleans_failed > 0:
        print(f"{cleans_failed} could not be deleted.")
        exit(1)


def metaverif(repo_path, tmpdir, file):
    # Extract the name using regex
    name_match = pkgs.re.search(r"([^/]*)(?=\.entry\.mpv)", file)
    if name_match:
        name = name_match.group(0)  # Get the matched name

        set_logging_logrecordfactory(name)
        logger.info(f"Start metaverif on {file}")

        # Create the file paths
        cpp_prep = pkgs.os.path.join(tmpdir, f"{name}.i.pv")
        awk_prep = pkgs.os.path.join(tmpdir, f"{name}.o.pv")

        # Output the results
        print(f"Name: {name}")
        print(f"CPP Prep Path: {cpp_prep}")
        print(f"AWK Prep Path: {awk_prep}")

        cpp(file, cpp_prep)
        parse_main(cpp_prep, awk_prep)
        # awk(repo_path, cpp_prep, awk_prep)

        log_file = pkgs.os.path.join(tmpdir, f"{name}.log")

        ta, res, ctr, expected, descs = pretty_output_init(cpp_prep)
        with open(log_file, "a") as log:
            generator = run_proverif(awk_prep, log_file)
            for line in generator:
                # parse-result-line:
                match = pkgs.re.search(r"^RESULT .* \b(true|false)\b\.$", line)
                if match:
                    result = match.group(1)
                    # pretty-output:
                    res, ctr, ta = pretty_output_step(
                        cpp_prep, result, expected, descs, res, ctr, ta
                    )
    else:
        logger.error(
            f"No match found for the filename {file}: extension should be .mpv"
        )
        exit(1)


@main.command()
@click.argument("i_path")
@click.argument("o_path")
def parse(i_path, o_path):
    if not pkgs.os.path.isfile(i_path):
        logger.error(f"{i_path} is not a file or does not exist.")
        exit(1)

    if i_path.lower().endswith(".pv"):
        logger.info(f"Parsing ProVerif .pv file {i_path}")
        try:
            parse_main(i_path, o_path)
        except pkgs.lark.exceptions.UnexpectedCharacters as e:
            logger.error(f"Error {type(e).__name__} parsing {i_path}: {e}")
    elif i_path.lower().endswith(".pcv"):
        with pkgs.tempfile.NamedTemporaryFile(suffix=".pv", delete_on_close=False) as f:
            m4(i_path, f)
            try:
                parse_main(f.name, o_path)
            except pkgs.lark.exceptions.UnexpectedCharacters as e:
                logger.error(f"Error {type(e).__name__} parsing {i_path}: {e}")

    else:
        logger.error(f"Unsupported file extension for file {i_path}")
        exit(2)


if __name__ == "__main__":
    main()
