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
@click.argument("log")
@click.argument("extra_args")
def run_proverif(file, log, extra_args):
    return exc(["proverif", "-test", *extra_args, file], stderr=pkgs.sys.stderr)


def clean_warnings():
    pass


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
