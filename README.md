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

For convenience, a full list of solution keys is stored encrypted in `solutions.txt.asc` using a "master password", which only the author should have access to.

Plain solution files are `.gitignore`d so that they do not get committed by accident.

### Settings

```toml
filepath = "path/to/solution"
template = "path/to/template/file"
test = "command to run %p"
```

`filepath` is the path template for each solution file. The problem number can be inserted via `%p` (simple) or `%P` (padded with zeros to 4 digits),
and the grid number (groups of 100 problems) via `%g`. Either `%p` or `%P` should be present.

`template` is an optional path to the template file. If present, its content will be copied to new solution files on `eulervault new`.
The template file can use the same placeholders `%p`, `%P`, and `%g`, and you can use `%%` to insert a literal `%`.

`test` is an optional shell command template to run when `eulervault test <problem>` is invoked.
It supports the same placeholders `%p`, `%P`, `%g`, and `%%` as the other settings.

## Usage

### `eulervault init`

Sets up the current folder for `eulervault`. You will be asked to set `filepath` and the master password. You can set `template` by manually editing `eulervault.toml` afterwards.

### `eulervault new <problem>`

Creates a new solution file for the problem number `<problem>`. If `template` is set, the file is populated with the template.

### `eulervault set <problem> <solution>`

When you have solved the problem `<problem>`, you can set the answer key for it. `eulervault` updates `solutions.txt.asc` and creates the locked version of the solution file for `<problem>`.
Then you can commit the new (encrypted) files to share your solution.

You can also update multiple keys in one command:

```bash
eulervault --set problem1=solution1 --set problem2=solution2
```

If the same problem appears multiple times in one invocation, only the first appearance is used.

### `eulervault update`

When you have updated one or more solution files after encrypting them, `eulervault update` updates the corresponding encrypted files.
Only the ones where `.asc` file is missing or older are re-encrypted.

### `eulervault master`

When you want to continue work on a different machine, you can clone your repo and use this command to unlock all solution files at once.

### `eulervault unlock <problem> <solution>`

Non-authors can use this command to unlock the solution file for `<problem>`.

### `eulervault test <problem>`

Runs the shell command defined in the `test` setting for the given problem number after substituting template placeholders.
Exits with an error if `test` is not configured or the command exits with a non-zero status.
