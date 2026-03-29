# Project Setup and Run Guide

This file is a separate run guide for the ElGamal Digital Signature project.

## 1. Required Software Installations

Install the following software before running the project:

- Python 3.10 or newer
- pip (Python package installer)
- Tkinter (usually included with standard Python on Windows)

Install required Python libraries:

```powershell
py -m pip install sympy matplotlib
```

Optional but recommended (virtual environment):

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
py -m pip install --upgrade pip
py -m pip install sympy matplotlib
```

## 2. Step-by-Step Execution Process

1. Open PowerShell in the project folder.
2. Move to the project directory:

```powershell
cd "D:\6th sem\Cryptography\REVIEW 2"
```

3. (Optional) Activate virtual environment:

```powershell
.\.venv\Scripts\Activate.ps1
```

4. Ensure dependencies are installed:

```powershell
py -m pip install sympy matplotlib
```

5. Run the GUI application:

```powershell
py elgamal_gui.py
```

6. In the application, execute in order:
- Click Generate Keys
- Click Run Attack (Bad k)
- Click Apply Prevention
- Click Show Graphs

## 3. Instructions to Run the Project

### Main Run Command

```powershell
py elgamal_gui.py
```

### What the project does when running

- Generates ElGamal keys
- Demonstrates vulnerable behavior in the before-fix phase
- Executes reused-k attack and shows attack logs
- Applies safe-signing prevention strategy
- Displays analytics graphs comparing before and after behavior

### If you get common errors

Import error for sympy:

```powershell
py -m pip install sympy
```

Import error for matplotlib:

```powershell
py -m pip install matplotlib
```

Tkinter not found:
- Reinstall Python from python.org and make sure Tcl/Tk and IDLE/Tkinter are included.

### Stop the application

- Close the GUI window, or press Ctrl+C in terminal if needed.
