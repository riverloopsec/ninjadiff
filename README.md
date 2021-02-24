# NinjaDiff

NinjaDiff is a binary diffing plugin for Binary Ninja. It aims to graphically display changes in differing binary executables. Check out our [blog post](https://www.riverloopsecurity.com/blog/2021/02/binary-diffing/) to read more about it's design!


This plugin uses [Hashashin](https://github.com/riverloopsec/hashashin) as a niave metric for binary similarity.  First, these hashes are used in conjunction with a graph similarity based approach to "align" similar functions accross binaries, then High Level IL instructions are compared line by line to give more granular information about subtle differences between the two binaries.


### Installation

Copy the contents of this repository into your Binary Ninja plugin directory (`Tools`--> `Open Plugin Folder...` in Binary Ninja)

The easiest way to do this is with `git clone --recursive …`, take care to ensure that the [Hashashin](https://github.com/riverloopsec/hashashin) sub-module get's pulled along with the rest of the repository, otherwise NinjaDiff will not function correctly. 



### Usage

1. Open your source binary as usual in Binary Ninja
2. Select `Diff` view from the dropdown in the lower right corner
3. Select the destination binary in the file selection menu
4. The destination binary will be opened in a split view, and the diffing process will begin (this may take some time on large binaries)
5. Once diffing is complete, any differences which are found will be added as tags, and will be highlighted red in the split screen view



### Known Bugs

* Due to limitations in Binary Ninja, some binaries will map multiple High Level IL instructions to a single address, which leads to false positives when these instructions are compared across binaries
* Due to similar limitations, some instructions may be highlighted or tagged multiple times if it's address collides with another instruction
* Certain HLIL instructions with complex or deeply nested ASTs may lead to false negatives due to binary artifacts
