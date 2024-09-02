# Introduction
## A quick guide to understanding the rest of the book

This book was inspired by the Little Schemer series of books, may it be
similarly unique and fun. The style is a blend of the Socratic dialogue from
it, and literate programming. It is presented in a code review format, which is
a common way for programmers to work together.

Each section is presented as a branch, within which each chapter is one code
review. Unlike traditional code review, these are more aimed at teaching rather
than ensuring style fits, and there are no obvious bugs in the code.

This book assumes some basic knowledge about how to edit text files, and how to
run commands from the command line. To follow along, you will also need the
following programs: a C compiler (I have used GCC while writing this book, but
Clang should work fine); and a Unix make program (I have used GNU make, if you
are using BSD make and something doesn't work, please open an issue on GitHub).
If you are on Linux or macOS then these are probably already installed. If you
are on Windows, I recommend the Windows Subsystem for Linux (version 2, also
called WSL2).

You should also have some awareness of how git groups changes into commits, and
how code review then consists of other programmers looking at those changes.
While you don't need knowledge of git itself to just read the book, it might
help if you want to follow along with the book. There is [the official
tutorial](https://git-scm.com/docs/gittutorial), as well as a lot of other
resources online.

I should point out, that the code review in this book is not typical, it is a
teaching aid -- normally code review is there to catch mistakes and style
inconsistencies.
