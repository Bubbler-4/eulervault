# Concept

Solution files are committed in the encrypted form, with the decryption key being the solution to each problem.

The solutions themselves are stored in a separate file, encrypted with a "master password".
This is useful e.g. when the user moves to a different machine.

## Encryption

`solution.txt` and the solution files are encrypted using AES256 and ascii-armored. The committed files will have the file extension `.asc`.

# Components

## Global setting file `eulervault.toml`

* `filepath`: a path pattern for the solution files. The pattern is a relative path from the root of the repository, and it can use the following placeholders:

  * `%p`: the problem number
  * `%P`: the problem number padded to four digits with leading zeros
  * `%g`: the grid number that the problem belongs to (e.g. 1-100 = grid 1, 101-200 = grid 2, etc.)

  One of `%p` and `%P` must be present. `%g` is optional.

* `template`: an optional path to a template file. If set, `eulervault new` initializes new solution files with this template's content after replacing `%p`, `%P`, and `%g`. Use `%%` to insert a literal `%`.

## Solutions file `solutions.txt`

This file contains solutions to all problems, with each line in the form of `problem=solution`. For example, if the solution to problem 1 is 123456789, the line will be `1=123456789`.

## Master password file `master_password.txt`

This file contains the master password for decrypting the solution files. This file is placed in the computer's config directory when the master password is set.

# Commands

## `eulervault init`

Sets up the current folder with the given global settings and the master password. Each setting is asked through a prompt.

This command also adds `solutions.txt` and the glob pattern matching the solution files to `.gitignore`.

## `eulervault new <problem>`

Creates a new solution file for the given problem number and prints the path to the file.
If the global `template` setting is set, the new file is initialized from the template file content with `%p`, `%P`, and `%g` placeholders replaced for the given problem.

## `eulervault migrate`

Prompts for a new `filepath` pattern, then checks problems 1 through 9999 and moves existing plaintext solution files and corresponding `.asc` files from the old rendered paths to the new rendered paths.
This command does not consult `solutions.txt`.
Files whose rendered old and new paths are identical are skipped.
If any destination path collides with a different file's source path, the command aborts before moving anything.

## `eulervault set <problem> <solution>`

Sets the solution for the given problem number. This will update `solutions.txt`, and encrypt the solution file and `solutions.txt`.

`--set` can also be repeated on the top-level command line to apply multiple updates in one run (for example, `eulervault --set 1=233168 --set 2=4613732`).
When the same problem appears multiple times in the same invocation, only the first appearance is applied.

## `eulervault update`

Reads `solutions.txt` and re-encrypts matching solution files only when the plaintext file is newer than the encrypted `.asc` file (or if the `.asc` file does not exist).

## `eulervault master`

For when the user moves to a different machine. Prompts the user for the master password, and if it successfully decrypts `solutions.txt`, decrypts all solution files and creates the master password file in the new machine.

## `eulervault change-master-password`

Works only when the master password file exists. Changes the master password and encrypts `solutions.txt` using the new master password.

## `eulervault unlock <problem> <solution>`

For other users browsing a `eulervault`-secured repository. Decrypts the given problem's solution file using the given solution and prints the path to the file. The solution file will contain garbage when the solution is incorrect.