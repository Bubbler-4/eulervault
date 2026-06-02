# eulervault

A simple tool to share solutions without compromising the integrity of Project Euler

## Installation

If you have Rust toolchain installed, you can install using the following command:

```bash
$ cargo install --git https://github.com/Bubbler-4/eulervault.git
```

Otherwise, you can grab the latest binaries (Windows/Linux) from [Releases](https://github.com/Bubbler-4/eulervault/releases).

## How it works

`eulervault` locks each solution file using the correct answer to the corresponding problem.
This way, other users who have already solved a problem can unlock and view your solution.

For convenience, a full list of solution keys is stored in `solutions.txt` and encrypted using a "master password", which only the author should have access to.

Plain solution files and `solutions.txt` are `.gitignore`d so that they do not get committed by accident.

### Settings

```toml
filepath = "path/to/solution"
template = "path/to/template/file"
```

`filepath` is the path template for each solution file. The problem number can be inserted via `%p` (simple) or `%P` (padded with zeros to 4 digits),
and the grid number (groups of 100 problems) via `%g`. Either `%p` or `%P` should be present.

`template` is an optional path to the template file. If present, its content will be copied to new solution files on `eulervault new`.
The template file can use the same placeholders `%p`, `%P`, and `%g`, and you can use `%%` to insert a literal `%`.

## Usage

### `eulervault init`

Sets up the current folder for `eulervault`. You will be asked to set `filepath` and the master password. You can set `template` by manually editing `eulervault.toml` afterwards.

### `eulervault new <problem>`

Creates a new solution file for the problem number `<problem>`. If `template` is set, the file is populated with the template.

### `eulervault set <problem> <solution>`

When you have solved the problem `<problem>`, you can set the answer key for it. `eulervault` updates `solutions.txt`, and creates the locked versions of `solutions.txt` and the solution file for `<problem>`.
Then you can commit the new (encrypted) files to share your solution.

### `eulervault update`

Reads `solutions.txt` and re-locks listed solution files only when the plaintext file is newer than its `.asc` file (or when the `.asc` file is missing). This is useful after editing multiple solution files.

### `eulervault master`

When you want to continue work on a different machine, you can clone your repo and use this command to unlock `solutions.txt` and all solution files at once.

### `eulervault unlock <problem>`

Non-authors can use this command to unlock the solution file for `<problem>`.
