#!/usr/bin/env python3
import re
import sys
import subprocess
import shelve
import os.path
from email.policy import default
from argparse import ArgumentParser, RawDescriptionHelpFormatter

ScsiGenericSysDir = "/sys/class/scsi_generic/"

usage = """sas-disks-id major purpose is to control the ident LEDs (typically blue and or flashing).
Additionally, it helps with mapping /dev/sd* devices to the enclosures (/dev/sg* devices) and slot index (default operation).
"""
parser = ArgumentParser(
    description=usage, formatter_class=RawDescriptionHelpFormatter)
parser.add_argument('-v', '--verbose', dest='verbose',
                    action='store_true', help='Verbose output.')
parser.add_argument('-D', '--debug', dest='debug',
                    action='store_true', help='Print debug messages.')
parser.add_argument('-q', '--quiet', dest='quiet',
                    action='store_true', help='Be quiet (=disable info logs).')
parser.add_argument('-c', '--use-cache', dest='useCache', action='store_true',
                    help="Use caches containing enclosure information. Useful to speedup scripts. THIS SHOULD only be used after running without cache since the last hardware modification! Otherwise the results might be WRONG!")
parser.add_argument('-e', '--enable-id', dest='enableId', action='store_true',
                    help="Enable the ident LED for the specified disks")
parser.add_argument('-d', '--disable-id', dest='disableId', action='store_true',
                    help="Disable the ident LED for the specified disks")
parser.add_argument("disks", nargs='+', help="Disks")

options = parser.parse_args()
if options.enableId and options.disableId:
    error("Enabling and disabling a disk's ident LED at the same time makes no sense. Please check the command line arguments and maybe usage (-h).", 1)


def debug(*text):
    if options.debug:
        print(*text)


def verbose(*text):
    if options.verbose:
        print(*text)


def info(*text):
    if not options.quiet:
        print(*text)


def error(text, exitCode=0):
    print(text, file=sys.stderr)
    if exitCode:
        sys.exit(exitCode)


def run(cmd, splitLinesBy='\n', check=False, errorLineFilter=None):
    debug("Running '%s'." % cmd)
    with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True) as p:
        stdout, stderr = p.communicate()
        out = stdout.decode('utf-8')
        err = stderr.decode('utf-8')
        ret = p.returncode

    if errorLineFilter:
        err = "\n".join(
            filter(lambda l: not errorLineFilter(l), err.split("\n")))
    if err:
        error("Cmd '%s' had error output:\n%s" % (cmd, err))
    if check and ret != 0:
        error("Cmd '%s' had a non-zero exit code:\n%i" % (ret), -2)

    return out.split(splitLinesBy) if splitLinesBy else out


def readFile(path, default=None):
    if not os.path.exists(path) and default:
        return default
    with open(path) as f:
        return f.read()


def getFromCache(name, compute):
    if options.useCache and name in cache:
        return cache[name]
    else:
        v = compute()
        cache[name] = v
        return v


sas2disk = {}
sdX2sas = {}
sas2sdX = {}


class Disk:
    def __init__(self, sasAddr, enc, sesAddr):
        self.sasAddr = sasAddr
        self.enc = enc
        self.sesAddr = sesAddr
        self.sdName = sas2sdX[sasAddr] if sasAddr in sas2sdX else None
        sas2disk[sasAddr] = self

    def __str__(self):
        return self.sdName

    def __repr__(self):
        return "Disk(%s, %s, %s, %s)" % (self.sdName, str(self.enc), self.sasAddr, self.sesAddr)


class Enclosure():
    def __init__(self, sgName):
        self.sgName = sgName
        self.model = readFile(ScsiGenericSysDir + sgName +
                              "/device/model", "UNKNOWN").strip()
        self.disks = None

    def __str__(self):
        return self.model + " (%s)" % self.sgName

    def __repr__(self):
        return "Enclosure(%s, %s)" % (self.sgName, self.model)

        return getFromCache(
            lambda: run()
        )

    def findDisks(self):
        disklines = getFromCache(
            self.sgName + '_ses_j',
            lambda: run(
                "sudo sg_ses  -j /dev/" + self.sgName +
                "| grep -E '^(\\[0,[0-9]+\\] *Element type: Array device slot| *number of phys: [0-9], not all phys: [0-9], device slot number: [0-9]+| *SAS address:)' | grep -v 'SAS address: 0x0$'",
                errorLineFilter=lambda line:
                line.startswith('warning:')
                or line.startswith('Invalid response, wanted page code:')
                or line.startswith(' 00     00 00 00 00')
            )
        )

        debug("Parsing this output of sg_ses:")
        index = None
        disks = []
        for l in disklines:
            debug("Line:" + l)

            indexOffset = 0
            m = re.match(
                '\\[0,([0-9]+)\\] *Element type: Array device slot', l)
            if not m:
                m = re.match('.*device slot number: ([0-9]+)', l)
                indexOffset = -1
            if m:
                index = int(m.group(1)) + indexOffset
                debug("Found index=%d" % index)
                continue

            m = re.match(' *SAS address: (0x[0-9a-f]+)', l)
            if m:
                sas = m.group(1)
                if index is None:
                    error("No index found for SAS address %s!" % sas)
                disks.append(Disk(sas, self, index))
                index = None
                debug("Found disk: %s" % repr(disks[-1]))
                continue

        return disks


if __name__ == "__main__":
    run("mkdir -p ~/.cache")

    with shelve.open(os.path.expanduser("~/.cache/sas-disks-id.cache")) as cache:
        enclosures = list(filter(lambda x: x, run(
            "grep -lF 13 %s*/device/type | grep -Eo sg[0-9]+" % ScsiGenericSysDir)))

        if not enclosures:
            error("No enclosures found!", 2)

        enclosures = [Enclosure(sgName) for sgName in enclosures]

        verbose("Found these enclosures:", ", ".join(map(repr, enclosures)))
        sdX2sas = dict({l.split(" ")[1]: l.split(" ")[0] for l in run("lsscsi -t | grep -oE '0x.*$'| sed -rs 's/ +\/dev\// /g'", errorLineFilter=lambda line: line.startswith('_tport: no sas_address, wd=/sys/class/sas_device/')
                                                                      ) if l})
        sas2sdX = {v: k for k, v in sdX2sas.items()}

        for enc in enclosures:
            enc.findDisks()

        if not sdX2sas:
            error("No disks with SAS-address found!", 3)

        for dPath in options.disks:
            d = os.path.basename(dPath)
            if not d in sdX2sas:
                error(
                    "%s does not seem to have a SAS address (see lsscsi -t) -- skipping!" % dPath)
                continue

            sasAddr = sdX2sas[d]
            if not sasAddr in sas2disk:
                error(
                    "Could not find %s(SAS:%s) within the enclosures -- skipping!" % (d, sasAddr))
                continue

            disk = sas2disk[sasAddr]
            assert disk.sdName == d

            if options.disableId:
                info("Turning OFF ident LED for '%s'." % disk)
                run("sudo sg_ses --index=%s --clear=ident /dev/%s" %
                    (disk.sesAddr, disk.enc.sgName))
            elif options.enableId:
                info("Turning ON ident LED for '%s'" % disk)
                run("sudo sg_ses --index=%s --set=ident /dev/%s" %
                    (disk.sesAddr, disk.enc.sgName))
            else:
                print("%s is in slot %d in enclosure %s" %
                      (disk, 1 + int(disk.sesAddr), disk.enc))
