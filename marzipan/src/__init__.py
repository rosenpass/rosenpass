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


def exc_piped(argv, **kwargs):
    eprint("$", *argv)
    return pkgs.subprocess.Popen(argv, **kwargs)


@click.command()
@click.argument("file")
@click.argument("extra_args", required=False)
def run_proverif(file, extra_args=[]):
    _run_proverif(file, extra_args)

def _run_proverif(file, extra_args=[]):
    if extra_args is None:
        extra_args = []
    params = ["proverif", "-test", *extra_args, file]
    print(params)
    eprint(params)

    process = exc_piped(params, stderr=pkgs.subprocess.PIPE, stdout=pkgs.subprocess.PIPE, text=True, bufsize=1)
    try:
        null, p = clean_warnings_init()
        for line in process.stdout:
            #print(f"received a line: {line.strip()}")
            # clean warnings
            line = line.rstrip()
            if not pkgs.re.match(r"^Warning: identifier \w+ rebound.$", line):
                if p != null:
                    yield p
                    #print(p)
                p = line
            else:
                p = null
        if p != null:
            yield p
            #print(p)
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        process.stdout.close()
        process.wait()


@click.command()
@click.argument("file")
@click.argument("cpp_prep")
def cpp(file, cpp_prep):
    _cpp(file, cpp_prep)


def _cpp(file, cpp_prep):
    print(f"_cpp: {file}, {cpp_prep}")
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
def awk(cpp_prep, awk_prep):
    _awk(cpp_prep, awk_prep)

def _awk(cpp_prep, awk_prep):
    params = ["awk", "-f", "marzipan/marzipan.awk", cpp_prep]
    with open(awk_prep, 'w') as file:
        exc(params, stderr=pkgs.sys.stderr, stdout=file)
        file.write("\nprocess main")



def pretty_output_line(prefix, mark, color, text):
    prefix = f"[grey42]{prefix}[/grey42]"
    content = f"[{color}]{mark} {text}[/{color}]"

    output = prefix + content
    rich_print(output)


def pretty_output_init(file_path):
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

    ta = pkgs.time.time()
    res = 0
    ctr = 0
    return ta, res, ctr, expected, descs


def pretty_output_step(file_path, line, expected, descs, res, ctr, ta):
    tz = pkgs.time.time()

    # Output from ProVerif contains a trailing newline, which we do not have in the expected output. Remove it for meaningful matching.
    outp_clean = line.rstrip()

    if outp_clean == expected[ctr]:
        pretty_output_line(f"{int(tz - ta)}s ", "✔", "green", descs[ctr])
    else:
        res = 1
        pretty_output_line(f"{int(tz - ta)}s ", "✖", "red", descs[ctr])

    ctr += 1
    ta = tz

    return res, ctr, ta


@click.command()
@click.argument("file_path")
def pretty_output(file_path):
    ta, res, ctr, expected, descs = pretty_output_init(file_path)
    for line in pkgs.sys.stdin:
        res, ctr, ta = pretty_output_step(file_path, line, expected, descs, res, ctr, ta)


@click.command()
@click.argument("path")
def analyze(path):
    pkgs.os.chdir(path)

    tmpdir = "target/proverif"
    pkgs.os.makedirs(tmpdir, exist_ok=True)

    entries = []
    entries.extend(sorted(pkgs.glob.glob('analysis/*.entry.mpv')))

    with pkgs.concurrent.futures.ProcessPoolExecutor() as executor:
        futures = {executor.submit(_metaverif, tmpdir, entry): entry for entry in entries}
        for future in pkgs.concurrent.futures.as_completed(futures):
            cmd = futures[future]
            try:
                #res = future.result()
                print(f"Metaverif {cmd} finished.", file=pkgs.sys.stderr)
            except Exception as e:
                print(f"Metaverif {cmd} generated an exception: {e}")

    print("all processes finished.")


@click.command()
def clean():
    click.echo("foo")
    pass


def clean_warnings_init():
    null = "0455290a-50d5-4f28-8008-3d69605c2835"
    p = null
    return null, p


def clean_warnings_line(null, p, line):
    line = line.rstrip()
    if not pkgs.re.match(r"^Warning: identifier \w+ rebound.$", line):
        if p != null:
            yield p
            print(p)
        p = line
    else:
        p = null
    return p


def clean_warnings_finalize(null, p):
    # print last line after EOF
    if p != null:
        yield p
        print(p)


@click.command()
def clean_warnings():
    #null = "0455290a-50d5-4f28-8008-3d69605c2835"
    #p = null
    null, p = clean_warnings_init()

    for line in pkgs.sys.stdin:
        p = clean_warnings_line(null, p, line)
        #line = line.rstrip()
        #if not pkgs.re.match(r"^Warning: identifier \w+ rebound.$", line):
        #    if p != null:
        #        print(p)
        #    p = line
        #else:
        #    p = null

    clean_warnings_finalize(null, p)
    ## print last line after EOF
    #if p != null:
    #    print(p)


@click.command()
@click.argument("tmpdir")
@click.argument("file")
def metaverif(tmpdir, file):
    metaverif(tmpdir, file)

def _metaverif(tmpdir, file):
    print(f"Start metaverif on {file}")
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

        _cpp(file, cpp_prep)
        _awk(cpp_prep, awk_prep)

        log_file = pkgs.os.path.join(tmpdir, f"{name}.log")

        ta, res, ctr, expected, descs = pretty_output_init(cpp_prep)
        with open(log_file, 'a') as log:
            generator = _run_proverif(awk_prep)
            for line in generator:
                log.write(line)
                # parse-result-line:
                match = pkgs.re.search(r'^RESULT .* \b(true|false)\b\.$', line)
                if match:
                    result = match.group(1)
                    #print(result, flush=True)
                    # pretty-output:
                    res, ctr, ta = pretty_output_step(cpp_prep, result, expected, descs, res, ctr, ta)
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
main.add_command(awk)
main.add_command(parse_result_line)
main.add_command(pretty_output)
main.add_command(clean_warnings)
