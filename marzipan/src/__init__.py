from .util import pkgs, setup_exports, export, rename
from rich import print as rich_print
import click


(__all__, export) = setup_exports()
export(setup_exports)


def eprint(*args, **kwargs):
    print(*args, **{"file": pkgs.sys.stderr, **kwargs})


def exc(argv, **kwargs):
    eprint("$", *argv)
    command = pkgs.subprocess.run(argv, **kwargs)
    if command.stdout is not None:
        return command.stdout.decode("utf-8")
    return ""


@click.command()
@click.argument("file")
@click.argument("extra_args", required=False)
def run_proverif(file, extra_args=[]):
    if extra_args is None:
        extra_args = []
    params = ["proverif", "-test", *extra_args, file]
    print(params)
    eprint(params)
    return exc(params, stderr=pkgs.sys.stderr)

@click.command()
@click.argument("file")
@click.argument("cpp_prep")
def cpp(file, cpp_prep):
    file_path = pkgs.pathlib.Path(file)

    dirname = file_path.parent
    cwd = pkgs.pathlib.Path.cwd()

    params = ["cpp", "-P", f"-I{cwd}/{dirname}", file, "-o", cpp_prep]
    return exc(params, stderr=pkgs.sys.stderr)


@click.command()
def parse_result_line():
    for outp in pkgs.sys.stdin:
        match = pkgs.re.search(r'^RESULT .* \b(true|false)\b\.$', outp)

        if match:
            result = match.group(1)
            print(result, flush=True)
        else:
            pass


@click.command()
@click.argument("cpp_prep")
@click.argument("awk_prep")
def awk_prep(cpp_prep, awk_prep):
    params = ["awk", "-f", "marzipan/marzipan.awk", cpp_prep]
    with open(awk_prep, 'w') as file:
        exc(params, stderr=pkgs.sys.stderr, stdout=file)
        file.write("\nprocess main")


def pretty_output_line(prefix, mark, color, text):
    prefix = f"[grey42]{prefix}[/grey42]"
    content = f"[{color}]{mark} {text}[/{color}]"

    output = prefix + content
    rich_print(output)


@click.command()
@click.argument("file_path")
def pretty_output(file_path):
    expected = []
    descs = []

    # Process lemmas first
    with open(file_path, 'r') as file:
        content = file.read()
        result = pkgs.re.findall(r'@(lemma)(?=\s+\"([^\"]*)\")', content)
        if result:
            expected.extend(['true' if e[0] == 'lemma' else e[0] for e in result])
            descs.extend([e[1] for e in result])

        # Then process regular queries
        result = pkgs.re.findall(r'@(query|reachable)(?=\s+"[^\"]*")', content)
        if result:
            expected.extend(['true' if e == '@query' else 'false' for e in result])
            reachable_result = pkgs.re.findall(r'@(query|reachable)\s+"([^\"]*)"', content)
            descs.extend([e[1] for e in reachable_result])

    res = 0
    ctr = 0
    ta = pkgs.time.time()

    for outp in pkgs.sys.stdin:
        tz = pkgs.time.time()

        # Output from ProVerif contains a trailing newline, which we do not have in the expected output. Remove it for meaningful matching.
        outp_clean = outp.rstrip()

        if outp_clean == expected[ctr]:
            pretty_output_line(f"{int(tz - ta)}s ", "✔", "green", descs[ctr])
        else:
            res = 1
            pretty_output_line(f"{int(tz - ta)}s ", "✖", "red", descs[ctr])

        ctr += 1
        ta = tz

    return res




@click.command()
@click.argument("command")
@click.argument("path")
def analyze(command, path):
    exc([
        f"{pkgs.pathlib.Path(__file__).resolve().parent}/analyze.sh",
        command,
        path
    ])


@click.command()
def clean():
    click.echo("foo")
    pass


@click.command()
def clean_warnings():
    null = "0455290a-50d5-4f28-8008-3d69605c2835"
    p = null
    for line in pkgs.sys.stdin:
        line = line.rstrip()
        if not pkgs.re.match(r"^Warning: identifier \w+ rebound.$", line):
            if p != null:
                print(p)
            p = line
        else:
            p = null
    # print last line after EOF
    if p != null:
        print(p)


@click.command()
@click.argument("tmpdir")
@click.argument("file")
def metaverif(tmpdir, file):
    pass


    # Extract the name using regex
    name_match = pkgs.re.search(r'([^/]*)(?=\.mpv)', file)
    if name_match:
        name = name_match.group(0)  # Get the matched name

        # Create the file paths
        cpp_prep = pkgs.os.path.join(tmpdir, f"{name}.i.pv")
        awk_prep = pkgs.os.path.join(tmpdir, f"{name}.o.pv")

        # Output the results
        print(f"Name: {name}")
        print(f"CPP Prep Path: {cpp_prep}")
        print(f"AWK Prep Path: {awk_prep}")

        cpp_prep(name, cpp_prep)
        awk_prep(cpp_prep, awk_prep)

        log_file = pkgs.os.path.join(tmpdir, f"{name}.log")

        with open(log_file, 'a') as log:
            run_proverif(awk_prep)



    else:
        print("No match found for the file name.")


@export
@rename("main") # Click seems to erase __name__
@click.group()
def main():
    #pkgs.IPython.embed()
    pass


main.add_command(analyze)
main.add_command(metaverif)
main.add_command(clean)
main.add_command(run_proverif)
main.add_command(cpp)
main.add_command(awk_prep)
main.add_command(parse_result_line)
main.add_command(pretty_output)
main.add_command(clean_warnings)
