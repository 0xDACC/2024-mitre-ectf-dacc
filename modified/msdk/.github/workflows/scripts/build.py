from pathlib import Path
import os
from subprocess import run
import argparse
from typing import Tuple
from rich.progress import Progress
from rich.console import Console
from rich.text import Text
import time
import shutil

blacklist = [
    "MAX32570",
    "MAX32572",
    "MAXREFDES178",
    "BCB", 
    "ROM", 
    "Simulation", 
    "BCB_PBM", 
    "Emulator", 
    "Emulator_NFC", 
    "EvKit_129B", 
    "EvKit_129C",
    "WLP_VAR",
    "WLP_DB",
    "TQFN_DB",
    "WLP_V1"
]

known_errors = [
    "ERR_NOTSUPPORTED",
    "ERR_LIBNOTFOUND",
    "[WARNING] - This tool does not handle keys in a PCI-PTS compliant way, only for test"
]

def build_project(project:Path, target, board, maxim_path:Path, distclean=False) -> Tuple[int, tuple]:
    clean_cmd = "make clean" if not distclean else "make distclean"
    res = run(clean_cmd, cwd=project, shell=True, capture_output=True, encoding="utf-8")

    # Test build
    build_cmd = f"make -r -j 8 --output-sync=target --no-print-directory TARGET={target} MAXIM_PATH={maxim_path.as_posix()} BOARD={board} FORCE_COLOR=1"
    res = run(build_cmd, cwd=project, shell=True, capture_output=True, encoding="utf-8")

    project_info = {
        "target":target,
        "project":project.name,
        "board":board,
        "path":project,
        "build_cmd":build_cmd,
        "stdout":res.stdout,
        "stderr":res.stderr
    }

    # Error check build command
    fail = (res.returncode != 0)
    warning = False
    known_error = False
    if res.stderr != None:
        for err in known_errors:
            if err in res.stderr:
                known_error = True
            elif err in res.stdout:
                # This case catches the output of the SBTs, which will print a warning
                # to stdout.  For these warnings, stderr is non-null but empty
                if res.stderr == '':
                    known_error = True
                    

    if fail and known_error: # build error
        fail = False
    elif res.stderr != None and res.stderr != '' and not known_error: # Build passed but with warnings
        warning = True

    # Clean before returning
    run("make clean", cwd=project, shell=True, capture_output=True, encoding="utf-8")

    return_code = 0
    if fail:
        return_code = 1
    elif warning:
        return_code = 2

    return (return_code, project_info)


def test(maxim_path : Path = None, targets=None, boards=None, projects=None):
    env = os.environ.copy()
    if maxim_path is None and "MAXIM_PATH" in env.keys():
        maxim_path = Path(env['MAXIM_PATH']).absolute()
    else:
        print("MAXIM_PATH not set.")
        return

    env["FORCE_COLOR"] = 1

    console = Console(emoji=False, color_system="standard")

    # Remove the periphdrivers build directory
    shutil.rmtree(Path(maxim_path) / "Libraries" / "PeriphDrivers" / "bin", ignore_errors=True)

    # Get list of target micros if none is specified
    if targets is None:
        targets = []

        for dir in os.scandir(f"{maxim_path}/Examples"):
            if dir.name not in blacklist:
                targets.append(dir.name) # Append subdirectories of Examples to list of target micros

        console.print(f"Detected target microcontrollers: {targets}")
    
    else:
        assert(type(targets) is list)
        console.print(f"Testing {targets}")

    # Enforce alphabetical ordering
    targets = sorted(targets)

    # Track failed projects for end summary
    failed = []
    warnings = []
    count = 0

    for target in sorted(targets):

        target_fails = 0
        target_warnings = 0

        # Get list of supported boards for this target.
        if boards is None:
            boards = []
            for dirpath, subdirs, items in os.walk(maxim_path / "Libraries" / "Boards" / target):
                if "board.mk" in items and Path(dirpath).name not in blacklist:
                    boards.append(Path(dirpath).name)

        else:
            assert(type(boards) is list)
            console.print(f"Testing {boards}")

        boards = sorted(boards) # Enforce alphabetical ordering
                
        # Get list of examples for this target.
        if projects is None:
            projects = []
            for dirpath, subdirs, items in os.walk(maxim_path / "Examples" / target):
                if 'Makefile' in items and ("main.c" in items or "project.mk" in items):
                    projects.append(Path(dirpath))

        else:
            assert(type(projects) is list)
            for dirpath, subdirs, items in os.walk(maxim_path / "Examples" / target):
                dirpath = Path(dirpath)
                if dirpath.name in projects:
                    projects.remove(dirpath.name)
                    projects.append(dirpath)


        console.print("====================")
        console.print(f"Found {len(projects)} projects for [bold cyan]{target}[/bold cyan]")
        console.print(f"Detected boards: {boards}")

        projects = sorted(projects) # Enforce alphabetical ordering
                

        with Progress(console=console) as progress:
            task_build = progress.add_task(description=f"{target}: PeriphDrivers", total=(len(projects) * len(boards)) + len(boards))

            periph_success = True

            # Find Hello_World and do a PeriphDriver build test first.
            hello_world = None
            for p in projects:
                if p.name == "Hello_World":
                    hello_world = p
            
            if hello_world is None:
                console.print(f"[red]Failed to locate Hello_World for {target}[/red]")
            else:
                for board in boards:
                    progress.update(task_build, description=f"[bold cyan]{target}[/bold cyan] ({board}) PeriphDriver", refresh=True)
                    (return_code, project_info) = build_project(hello_world, target, board, maxim_path, distclean=True)
                    count += 1

                    # Error check build command
                    if return_code == 0:
                        progress.update(task_build, advance=1, description=f"[bold cyan]{target}[/bold cyan] ({board}): [green]PeriphDriver build pass.[/green]", refresh=True)
                    elif return_code == 1:
                        console.print(f"\n[red]{target} ({board}): PeriphDriver build failed.[/red]")
                        print(f"Build command: {project_info['build_cmd']}")
                        console.print("[bold]Errors:[/bold]")
                        console.print("[red]----------------------------------------[/red]")
                        console.print(Text.from_ansi(project_info['stderr']), markup=False)
                        console.print("[red]----------------------------------------[/red]\n")

                        if project_info not in failed:
                            failed.append(project_info)
                            target_fails += 1

                        periph_success = False
                        progress.update(task_build, advance=1, description=f"[bold cyan]{target}[/bold cyan] ({board}): [red]PeriphDriver build fail.[/red]", refresh=True)
                    elif return_code == 2:
                        console.print(f"\n[yellow]{target} ({board}): PeriphDriver built with warnings.[/yellow]")
                        print(f"Build command: {project_info['build_cmd']}")
                        console.print("[bold]Warnings:[/bold]")
                        console.print("[yellow]----------------------------------------[/yellow]")
                        console.print(Text.from_ansi(project_info['stderr']), markup=False)
                        console.print("[yellow]----------------------------------------[/yellow]\n")

                        if project_info not in warnings:
                            warnings.append(project_info)
                            target_warnings += 1

            if periph_success:
                # Iteratively across and test example projects
                for project in projects:
                    project_name = project.name

                    for board in boards:
                        progress.update(task_build, advance=1, description=f"{target} ({board}): {project_name}", refresh=True)

                        (return_code, project_info) = build_project(project, target, board, maxim_path, distclean=False)

                        # Error check build command
                        if return_code == 1:                            
                            console.print(f"\n[red]{target} ({board}): {project_name} failed.[/red]")
                            print(f"Build command: {project_info['build_cmd']}")
                            console.print("[bold]Errors:[/bold]")
                            console.print("[red]----------------------------------------[/red]")
                            console.print(Text.from_ansi(project_info['stderr']), markup=False)
                            console.print("[red]----------------------------------------[/red]\n")

                            if project_info not in failed:
                                failed.append(project_info)
                                target_fails += 1

                        elif return_code == 2:
                            console.print(f"\n[yellow]{target} ({board}): {project_name} built with warnings.[/yellow]")
                            print(f"Build command: {project_info['build_cmd']}")
                            console.print("[bold]Warnings:[/bold]")
                            console.print("[yellow]----------------------------------------[/yellow]")
                            console.print(Text.from_ansi(project_info['stderr']), markup=False)
                            console.print("[yellow]----------------------------------------[/yellow]\n")

                            if project_info not in warnings:
                                warnings.append(project_info)
                                target_warnings += 1

                        count += 1

            if target_warnings != 0:
                console.print(f"[bold cyan]{target}[/bold cyan]: [yellow]{target_warnings} projects built with warnings.[/yellow]")

            if target_fails == 0:
                progress.update(task_build, description=f"[bold cyan]{target}[/bold cyan]: [green]Pass.[/green]", refresh=True)
            elif not periph_success:
                progress.update(task_build, description=f"[bold cyan]{target}[/bold cyan]: [red]PeriphDriver build failed.[/red]", refresh=True)
            else:
                progress.update(task_build, description=f"[bold cyan]{target}[/bold cyan]: [red]Failed for {target_fails}/{len(projects)} projects[/red]", refresh=True)            

        boards = None # Reset boards list
        projects = None # Reset projects list

    console.print(f"Tested {count} cases.  {count - len(failed)}/{count} succeeded.")
    if (len(warnings) > 0):
        print(f"{len(warnings)} projects with warnings:")
        for p in warnings:
            console.print(f"[bold cyan]{p['target']}[/bold cyan]: [bold]{p['project']}[/bold] [yellow]warnings[/yellow] for [yellow]{p['board']}[/yellow]")
    
    if (len(failed) > 0):
        print("Failed projects:")
        for p in failed:
            console.print(f"[bold cyan]{p['target']}[/bold cyan]: [bold]{p['project']}[/bold] [red]failed[/red] for [yellow]{p['board']}[/yellow]")

        return -1
    else:
        console.print("[bold][green]Test pass.[/bold][/green]")
        return 0

parser = argparse.ArgumentParser("MSDK Build Test Script")
parser.add_argument("--maxim_path", type=str, help="(Optional) Location of the MaximSDK.  If this is not specified then the script will attempt to use the MAXIM_PATH environment variable.")
parser.add_argument("--targets", type=str, nargs="+", required=False, help="Target microcontrollers to test.")
parser.add_argument("--boards", type=str, nargs="+", required=False, help="Boards to test.  Should match the BSP folder-name exactly.")
parser.add_argument("--projects", type=str, nargs="+", required=False, help="Examples to populate.  Should match the example's folder name.")

if __name__ == "__main__":
    args = parser.parse_args()
    exit(
        test(
            maxim_path=args.maxim_path,
            targets=args.targets,
            boards=args.boards,
            projects=args.projects
        )
    )
