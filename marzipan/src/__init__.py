from .util import pkgs, setup_exports, export, rename
from rich import print
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
@click.argument("prefix")
@click.argument("mark")
@click.argument("color")
@click.argument("text")
def pretty_output_line(prefix, mark, color, text):
    colored_prefix = f"[grey42]{prefix}[/grey42]"
    colored_mark_text = f"[{color}]{mark} {text}[/{color}]"
    print(colored_prefix, colored_mark_text)


@click.command()
@click.argument("path")
def analyze(path):
    exc([
        f"{pkgs.pathlib.Path(__file__).resolve().parent}/analyze.sh",
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
main.add_command(pretty_output_line)
main.add_command(clean_warnings)
