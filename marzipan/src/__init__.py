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
@click.argument("cpp_prep")
@click.argument("awk_prep")
def awk_prep(cpp_prep, awk_prep):
    params = ["awk", "-f", "marzipan/marzipan.awk", cpp_prep]
    with open(awk_prep, 'w') as file:
        exc(params, stderr=pkgs.sys.stderr, stdout=file)
        file.write("\nprocess main")


@click.command()
@click.argument("prefix")
@click.argument("mark")
@click.argument("color")
@click.argument("text")
def pretty_output_line(prefix, mark, color, text):
    colored = f"[grey42]{prefix}[/grey42][{color}]{mark} {text}[/{color}]"
    rich_print(colored)


@click.command()
@click.argument("file")
def pretty_output(file_path):
    expected = []
    descs = []

    # Process lemmas first
    with open(file_path, 'r') as file:
        content = file.read()
        expected += pkgs.re.findall(r'@(lemma)(?=\s+"[^\"]*")', content)
        expected = ['true' if e == '@lemma' else e for e in expected]
        descs += pkgs.re.findall(r'@(lemma)\s+"([^\"]*)"', content)
        descs = [d[1] for d in descs]

        # Then process regular queries
        expected += pkgs.re.findall(r'@(query|reachable)(?=\s+"[^\"]*")', content)
        expected = ['true' if e == '@query' else 'false' for e in expected]
        descs += pkgs.re.findall(r'@(query|reachable)\s+"([^\"]*)"', content)
        descs = [d[1] for d in descs]

    res = 0
    ctr = 0
    ta = pkgs.time.time()

    for outp in expected:
        tz = pkgs.time.time()
        if outp == expected[ctr]:
            pretty_output_line(f"{int(tz - ta)}s ", "✔", "green", descs[ctr])
        else:
            res = 1
            pretty_output_line(f"{int(tz - ta)}s ", "✖", "red", descs[ctr])
        print()

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


@export
@rename("main") # Click seems to erase __name__
@click.group()
def main():
    #pkgs.IPython.embed()
    pass


main.add_command(analyze)
main.add_command(clean)
main.add_command(run_proverif)
main.add_command(cpp)
main.add_command(awk_prep)
main.add_command(pretty_output_line)
main.add_command(pretty_output)
main.add_command(clean_warnings)
