# Crytwi: Cryptic Twilight

A secure file encryption library with few examples, designed as a Bachelor's thesis project.

> Rapid developments are in progress!

## Install
Some ways require clone this repository first.

### Dependencies
Some functions in Crytwi like Argon2id KDF require higher version of Cryptography (>= 44) and OpenSSL (>= 3.2).

For debian package, we've forced **libssl** version up to 3.5 or higher.
Crytwi provides several ways to install.

### Using Virtual Environment
After create a virtual environment, go to root of repository and then just run:

```
pip install .
```

**ATTENTIONS: Make sure target system has installed OpenSSL 3.2 or higher, otherwise Crytwi will fail to work!**

### Using Debian package
Again, we've forced **libssl** version up to 3.5 or higher. **So this package can not natively installed on release below forky (14).**

#### QUICK: Fetch packages from Github release
Download `*.deb` and just use `apt` to install them, apt's super cow power will helps you install dependencies.

#### Build Debian packages
Go to root of this repository and run:
```
apt build-dep .
```
to install build dependencies, then:
```
dpkg-buildpackage -b
```
to build binary packages, you can see **dpkg-buildpackage(1)** for more options.

After build, go to parent directory to find debs, then use `apt` to install them, apt's super cow power will helps you install dependencies.

## How to use
> Man pages are underwriting now. Currently unavailable for actual development references.

Manual pages are included in this project. You can use the `man` command to view them, mostly under section 3.

Example codes like `./src/crytwi/cli.py` and files under `tests/` are good references.

## Changelogs
Currently, see `debian/changelog`. 
