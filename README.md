# Purpose
Decode macOS .savedState folders, located in `~/Library/Saved Application State`
# Usage
`python macOS_savedstate.py lo.cafe.lo-rain.savedState out` (folder `out/` must exist, this program will not make it.)

# Setup
Tested with macOS 14.1.1, dependencies frozen in conda.

To replicate my environment, have conda installed, and run `conda env create -f environment.yml`, then `conda activate macOS.savedState`. *Then* you can use the program without worry about mismatched dependencies.

All that really matters in the `environment.yml` (I believe) is python=3.11.5 and hexdump==3.3. Other versions may work but I haven't tested.

# Credit

All credit goes to Willi Ballenthin, the code is all his

https://gist.github.com/williballenthin/994db929b1448fdf73baf91207129dec `macOS_savedstate.py`

https://gist.github.com/williballenthin/ab23abd5eec5bf5a272bfcfb2342ec04 bplist.py (renamed to `zbplist.py`)

