import sys
import re, operator, string
from optparse import OptionParser, OptionGroup
import time

VERSION = "0.0.3"

class StatsGen:
    def __init__(self):
        self.output_file = None

        # Filters
        self.minlength   = None
        self.maxlength   = None
        self.simplemasks = None
        self.charsets    = None
        self.quiet = False
        self.debug = True

        # Stats dictionaries
        self.stats_length = dict()
        self.stats_simplemasks = dict()
        self.stats_advancedmasks = dict()
        self.stats_charactersets = dict()

        # Ignore stats with less than 1% coverage
        self.hiderare = False

        self.filter_counter = 0
        self.total_counter = 0

        # Minimum password complexity counters
        self.mindigit   = None
        self.minupper   = None
        self.minlower   = None
        self.minspecial = None

        self.maxdigit   = None
        self.maxupper   = None
        self.maxlower   = None
        self.maxspecial = None

    def analyze_password(self, password):

        # Password length
        pass_length = len(password)

        # Character-set and policy counters
        digit = 0
        lower = 0
        upper = 0
        special = 0

        simplemask = list()
        advancedmask_string = ""

        # Detect simple and advanced masks
        for letter in password:
 
            if letter in string.digits:
                digit += 1
                advancedmask_string += "?d"
                if not simplemask or not simplemask[-1] == 'digit': simplemask.append('digit')

            elif letter in string.lowercase:
                lower += 1
                advancedmask_string += "?l"
                if not simplemask or not simplemask[-1] == 'string': simplemask.append('string')


            elif letter in string.uppercase:
                upper += 1
                advancedmask_string += "?u"
                if not simplemask or not simplemask[-1] == 'string': simplemask.append('string')

            else:
                special += 1
                advancedmask_string += "?s"
                if not simplemask or not simplemask[-1] == 'special': simplemask.append('special')


        # String representation of masks
        simplemask_string = ''.join(simplemask) if len(simplemask) <= 3 else 'othermask'

        # Policy
        policy = (digit,lower,upper,special)

        # Determine character-set
        if   digit and not lower and not upper and not special: charset = 'numeric'
        elif not digit and lower and not upper and not special: charset = 'loweralpha'
        elif not digit and not lower and upper and not special: charset = 'upperalpha'
        elif not digit and not lower and not upper and special: charset = 'special'

        elif not digit and lower and upper and not special:     charset = 'mixedalpha'
        elif digit and lower and not upper and not special:     charset = 'loweralphanum'
        elif digit and not lower and upper and not special:     charset = 'upperalphanum'
        elif not digit and lower and not upper and special:     charset = 'loweralphaspecial'
        elif not digit and not lower and upper and special:     charset = 'upperalphaspecial'
        elif digit and not lower and not upper and special:     charset = 'specialnum'

        elif not digit and lower and upper and special:         charset = 'mixedalphaspecial'
        elif digit and not lower and upper and special:         charset = 'upperalphaspecialnum'
        elif digit and lower and not upper and special:         charset = 'loweralphaspecialnum'
        elif digit and lower and upper and not special:         charset = 'mixedalphanum'
        else:                                                   charset = 'all'

        return (pass_length, charset, simplemask_string, advancedmask_string, policy)

    def generate_stats(self, filename):
        """ Generate password statistics. """

        with open(filename, 'r') as f:

            for password in f:
                password = password.rstrip('\r\n')

                if len(password) == 0: continue

                self.total_counter += 1  

                (pass_length,characterset,simplemask,advancedmask, policy) = self.analyze_password(password)
                (digit,lower,upper,special) = policy

                if (self.charsets == None    or characterset in self.charsets) and \
                   (self.simplemasks == None or simplemask in self.simplemasks) and \
                   (self.maxlength == None   or pass_length <= self.maxlength) and \
                   (self.minlength == None   or pass_length >= self.minlength):

                    self.filter_counter += 1

                    if self.mindigit == None or digit < self.mindigit: self.mindigit = digit
                    if self.maxdigit == None or digit > self.maxdigit: self.maxdigit = digit

                    if self.minupper == None or upper < self.minupper: self.minupper = upper
                    if self.maxupper == None or upper > self.maxupper: self.maxupper = upper

                    if self.minlower == None or lower < self.minlower: self.minlower = lower
                    if self.maxlower == None or lower > self.maxlower: self.maxlower = lower

                    if self.minspecial == None or special < self.minspecial: self.minspecial = special
                    if self.maxspecial == None or special > self.maxspecial: self.maxspecial = special

                    if pass_length in self.stats_length:
                        self.stats_length[pass_length] += 1
                    else:
                        self.stats_length[pass_length] = 1

                    if characterset in self.stats_charactersets:
                        self.stats_charactersets[characterset] += 1
                    else:
                        self.stats_charactersets[characterset] = 1

                    if simplemask in self.stats_simplemasks:
                        self.stats_simplemasks[simplemask] += 1
                    else:
                        self.stats_simplemasks[simplemask] = 1

                    if advancedmask in self.stats_advancedmasks:
                        self.stats_advancedmasks[advancedmask] += 1
                    else:
                        self.stats_advancedmasks[advancedmask] = 1

    def print_stats(self):
        """ Print password statistics. """

        print "[+] Analyzing %d%% (%d/%d) of passwords" % (self.filter_counter*100/self.total_counter, self.filter_counter, self.total_counter)
        print "    NOTE: Statistics below is relative to the number of analyzed passwords, not total number of passwords"
        print "\n[*] Length:"
        for (length,count) in sorted(self.stats_length.iteritems(), key=operator.itemgetter(1), reverse=True):
            if self.hiderare and not count*100/self.filter_counter > 0: continue
            print "[+] %25d: %02d%% (%d)" % (length, count*100/self.filter_counter, count)

        print "\n[*] Character-set:"
        for (char,count) in sorted(self.stats_charactersets.iteritems(), key=operator.itemgetter(1), reverse=True):
            if self.hiderare and not count*100/self.filter_counter > 0: continue
            print "[+] %25s: %02d%% (%d)" % (char, count*100/self.filter_counter, count)

        print "\n[*] Password complexity:"
        print "[+]                     digit: min(%s) max(%s)" % (self.mindigit, self.maxdigit)
        print "[+]                     lower: min(%s) max(%s)" % (self.minlower, self.maxlower)
        print "[+]                     upper: min(%s) max(%s)" % (self.minupper, self.maxupper)
        print "[+]                   special: min(%s) max(%s)" % (self.minspecial, self.maxspecial)

        print "\n[*] Simple Masks:"
        for (simplemask,count) in sorted(self.stats_simplemasks.iteritems(), key=operator.itemgetter(1), reverse=True):
            if self.hiderare and not count*100/self.filter_counter > 0: continue
            print "[+] %25s: %02d%% (%d)" % (simplemask, count*100/self.filter_counter, count)

        print "\n[*] Advanced Masks:"
        for (advancedmask,count) in sorted(self.stats_advancedmasks.iteritems(), key=operator.itemgetter(1), reverse=True):
            if count*100/self.filter_counter > 0:
                print "[+] %25s: %02d%% (%d)" % (advancedmask, count*100/self.filter_counter, count)

            if self.output_file:
                self.output_file.write("%s,%d\n" % (advancedmask,count))

if __name__ == "__main__":

    header  = "                       _ \n"
    header += "     StatsGen %s   | |\n"  % VERSION
    header += "      _ __   __ _  ___| | _\n"
    header += "     | '_ \ / _` |/ __| |/ /\n"
    header += "     | |_) | (_| | (__|   < \n"
    header += "     | .__/ \__,_|\___|_|\_\\\n"
    header += "     | |                    \n"
    header += "     |_| iphelix@thesprawl.org\n"
    header += "\n"

    parser = OptionParser("%prog [options] passwords.txt\n\nType --help for more options", version="%prog "+VERSION)

    filters = OptionGroup(parser, "Password Filters")
    filters.add_option("--minlength", dest="minlength", type="int", metavar="8", help="Minimum password length")
    filters.add_option("--maxlength", dest="maxlength", type="int", metavar="8", help="Maximum password length")
    filters.add_option("--charset", dest="charsets", help="Password charset filter (comma separated)", metavar="loweralpha,numeric")
    filters.add_option("--simplemask", dest="simplemasks",help="Password mask filter (comma separated)", metavar="stringdigit,allspecial")
    parser.add_option_group(filters)

    parser.add_option("-o", "--output", dest="output_file",help="Save masks and stats to a file", metavar="password.masks")
    parser.add_option("--hiderare", action="store_true", dest="hiderare", default=False, help="Hide statistics covering less than 1% of the sample")

    parser.add_option("-q", "--quiet", action="store_true", dest="quiet", default=False, help="Don't show headers.")
    (options, args) = parser.parse_args()

    # Print program header
    if not options.quiet:
        print header

    if len(args) != 1:
        parser.error("no passwords file specified")
        exit(1)

    print "[*] Analyzing passwords in [%s]" % args[0]

    statsgen = StatsGen()

    if not options.minlength   == None: statsgen.minlength   = options.minlength
    if not options.maxlength   == None: statsgen.maxlength   = options.maxlength
    if not options.charsets    == None: statsgen.charsets    = [x.strip() for x in options.charsets.split(',')]
    if not options.simplemasks == None: statsgen.simplemasks = [x.strip() for x in options.simplemasks.split(',')]

    if options.hiderare: statsgen.hiderare = options.hiderare

    if options.output_file:
        print "[*] Saving advanced masks and occurrences to [%s]" % options.output_file
        statsgen.output_file = open(options.output_file, 'w')

    statsgen.generate_stats(args[0])
    statsgen.print_stats()



�
�J\c           @   s!   d  d l  Z  e  j d � d Ud S(   i����Nt� c        ��  @   sG d  d l  Z  d d d d d d d d	 d
 d d d
d d d d d d d d d d d d d d d d d d d  d! d" d d# d# d$ d% d d
 d& d' d d( d( d) d* d d+ d, d- d d& d. d/ d d0 d1 d2 d3 d4 d5 d6 d7 d
d8 d d4 d9 d: d; d2 d< d= d d d> d? d@ dA dB dC dD d) d dE dF dG dA dH dI dJ dK dL dM dN dO dP dQ dR d7 d6 dS dL dT d! dU dV dW d dX dY d5 d* dZ d dB d[ d\ d d] d^ dX d< d_ d` dG dF d/ da d3 d d db d dc dd d da de df dg dh dJ di d dj d
d dk dl d dI dm dn d do d dp dq dr d+ ds dt du dj dv dw dx dy d dC dv dz d{ d3 d d| d} d~ dV d| d d7 d� d� d7 d� d� d� d� d� dj d� d� dU d� d� dh d? d d+ dO d2 d� d d� dr d d� d� d� d� d� d� dN d d d� ds di d� d' dh d� d� dF d� d* d) d� d� d� d� d� d� d� d� d" d� d d@ d� d� d d+ d- dV d d� d� du dL d� da d- d� d� d d� d d d d dx d� d  d dA d3 d d� d� d� dG d d d dl d d d� d d� d1 d  dy d d d# d� d$ d% d� d
 d& d d d( d= d) d* d d+ d, d� d d& d� d/ d dI d1 d2 d� d4 d5 d6 d7 d
dg d d4 d� d: d; d d< d= dx d d> d� d@ dA d� dC dD d d dE d� dG dA d� dI dJ d dL dM d� dO dP d� dR d7 dK dS dL d� d! dU d{ dW d d� dY d5 d� dZ d d] d[ d\ d7 d] d^ d� d< d_ d� dG dF dQ da d3 d� d db d� dc dd d� da de d� dg dh d� di d d? d
d d� dl d d� dm dn d do d d� dq dr dg ds dt d� dj dv d dx dy d� dC dv dV d{ d3 d� d| d} d dV d| dX d7 d� de d7 d� dO d� d� d� dj d� dN dU d� d� dh d? d d+ dO d d� d d� dr d dP d� d� d� d� d� d3 d d d� ds di dg d' dh dr d� dF d� d* d) dc d� d� d� d� d� d� d� d" d� d d@ d� d� d d� d- dV dN d� d� d9 dL d� d d- d� d� d d� d� d d d� dx d� d d dA d� d d� dT d� dG d� d d d� d d dC d d� d d  dy d� d d# d+ d$ d% di d
 d& d d d( d d) d* d� d+ d, d� d d& d� d/ d d) d1 d2 d� d4 d5 d d7 d
df d d4 d7 d: d; d^ d< d= d� d d> d� d@ dA d� dC dD d� d dE dl dG dA dA dI dJ d& dL dM d dO dP d� dR d7 d� dS dL d d! dU d dW d d� dY d5 d� dZ d d� d[ d\ dV d] d^ d� d< d_ d� dG dF d� da d3 d� d db d� dc dd d
 da de d� dg dh d� di d d; d
d da dl d d� dm dn do do d d� dq dr di ds dt d{ dj dv d9 dx dy dK dC dv d� d{ d3 dr d| d} d� dV d| d� d7 d� d
 d7 d� d� d� d� dM dj d� d~ dU d� dv dh d? d d+ dO dq d� d d� dr d d� d� d� d� d� d� dx d d d ds di d� d' dh d� d� dF dg d* d) d� d� d� d6 d� d� d� d� d" d� d d@ d d� d d� d- dV d� d� d� dI dL d� d� d- d� d� d d� d d d d' dx d� d7 d dA d� d d� d� d� dG du d d d d d dq d d� d d  dy d d d# d d$ d% dD d
 d& d' d d( d� d) d* d d+ d, d- d d& d� d/ d d� d1 d2 d3 d4 d5 d� d7 d
d� d d4 d9 d: d; dZ d< d= d� d d> d? d@ dA d] dC dD d) d dE dO dG dA dd dI dJ df dL dM dN dO dP d^ dR d7 d� dS dL dq d! dU d� dW d d� dY d5 d* dZ d d� d[ d\ d> d] d^ d d< d_ dd dG dF d� da d3 d d db d dc dd dI da de d� dg dh d� di d d d
d d" dl d dc dm dn d� do d d� dq dr dY ds dt d� dj dv d� dx dy d$ dC dv d d{ d3 d� d| d} dv dV d| d� d7 d� d� d7 d� d� d� d� d� dj d� d� dU d� dr dh d? dE d+ dO dP d� d dQ dr d d� d� d� d� d� d� d� d d dG ds di dJ d' dh d� d� dF d� d* d) d� d� d� d� d� d� d
 d� d" dP d d@ d� d� d d� d- dV dO d� d� du dL d� d� d- d� d� d d� du d d d� dx d� d� d dA dm d d� d� d� dG d4 d d dy d d d� d d� d d  dy d d d# d� d$ d% d� d
 d& d d d( dS d) d* d� d+ d, dh d d& dK d/ d dj d1 d2 d� d4 d5 d d7 d
da d d4 d� d: d; d d< d= d� d d> d� d@ dA d� dC dD d' d dE d dG dA d; dI dJ d� dL dM d� dO dP d2 dR d7 dT dS dL dr d! dU d� dW d d� dY d5 d� dZ d d d[ d\ d\ d] d^ d� d< d_ d� dG dF d� da d3 d
 d db d� dc dd d� da de d� dg dh de di d d7 d
d dZ dl d d> dm dn de do d d� dq dr d0 ds dt d� dj dv d  dx dy d� dC dv dV d{ d3 d[ d| d} dC dV d| d+ d7 d� d� d7 d� d� d� d� d� dj d� dB dU d� d� dh d? d� d+ dO d6 d� d d� dr d dP d� d� d� d� d� d3 d d d, ds di d� d' dh dr d� dF d< d* d) d% d� d� dV d� d� dn d� d" d� d d@ dc d� d d� d- dV d� d� d� d dL d� d0 d- d� d� d d� d� d d d� dx d� d� d dA d@ d d� dT d� dG d� d d d� d d dC d d� d d  dy d
 d d# d+ d$ d% dP d
 d& d+ d d( d d) d* d� d+ d, d� d d& d� d/ d d) d1 d2 d� d4 d5 d d7 d
df d d4 d� d: d; d^ d< d= d� d d> d� d@ dA d� dC dD d� d dE d� dG dA dA dI dJ d& dL dM d^ dO dP d� dR d7 d� dS dL d d! dU d dW d d� dY d5 d� dZ d d� d[ d\ dV d] d^ d d< d_ d� dG dF d� da d3 dJ d db d� dc dd d� da de d? dg dh d� di d dB d
d d, dl d d� dm dn d' do d d� dq dr di ds dt dt dj dv d� dx dy dK dC dv d� d{ d3 d d| d} d� dV d| d0 d7 d� d" d7 d� d� d� d� d� dj d� d� dU d� dv dh d? dM d+ dO d� d� d d� dr d dC d� d� dF d� d� dx d d d� ds di d� d' dh d� d� dF dg d* d) d� d� d� d6 d� d� d d� d" d� d d@ d d� d d� d- dV dW d� d� d� dL d� d� d- d� dO d d� d d d d� dx d� d7 d dA d� d d� d� d� dG d� d d d� d d dF d d� d� d  dy d d d# d� d$ d% d� d
 d& d� d d( d( d) d* d d+ d, d� d d& dw d/ d d0 d1 d2 dk d4 d5 dd d7 d
d d d4 d9 d: d; d2 d< d= d� d d> d4 d@ dA d� dC dD d� d dE d� dG dA d dI dJ d� dL dM d� dO dP dQ dR d7 d� dS dL dq d! dU d� dW d d� dY d5 d* dZ d dB d[ d\ d> d] d^ d� d< d_ d� dG dF d: da d3 dT d db d� dc dd d� da de d� dg dh d� di d d� d
d d" dl d dI dm dn d[ do d dA dq dr d ds dt d� dj dv dj dx dy d# dC dv d� d{ d3 d� d| d} dR dV d| d� d7 d� d� d7 d� d� d� d� d� dj d� d$ dU d� d] dh d? d� d+ dO d6 d� d do dr d dh d� d� d{ d� d� d� d d dF ds di d� d' dh dH d� dF d� d* d) d� d� d� d� d� d� d' d� d" d� d d@ d� d� d dn d- dV db d� d� d� dL d� d� d- d� d� d d� d' d d d� dx d� d� d dA dm d d� d� d� dG d� d d d� d d d d d� d d  dy d d d# d d$ d% d[ d
 d& d� d d( d d) d* d� d+ d, dS d d& d� d/ d d; d1 d2 dy d4 d5 d/ d7 d
d� d d4 d� d: d; d� d< d= dk d d> d1 d@ dA d� dC dD d� d dE du dG dA d� dI dJ dP dL dM d� dO dP d� dR d7 d dS dL d� d! dU d6 dW d d� dY d5 d� dZ d dm d[ d\ d� d] d^ d� d< d_ d= dG dF d� da d3 d� d db d� dc dd d^ da de d� dg dh ds di d dH d
d dv dl d d� dm dn d3 do d dv dq dr d ds dt db dj dv d� dx dy d� dC dv d� d{ d3 d� d| d} d� dV d| dS d7 d� d� d7 d� d� d� d� d� dj d� d dU d� da dh d? d5 d+ dO d  d� d d� dr d d	 d� d� dm d� d� dY d d d� ds di d� d' dh d� d� dF d� d* d) d� d� d� d& d� d� d d� d" d� d d@ d� d� d d� d- dV d� d� d� dC dL d� d� d- d� d� d d� dO d d d� dx d� d� d dA d� d d� d� d� dG d� d d d� d d d d d� d� d  dy d� d d# d� d$ d% d� d
 d& d� d d( d d) d* d� d+ d, d� d d& dX d/ d da d1 d2 dh d4 d5 d+ d7 d
dy d d4 d� d: d; d� d< d= d� d d> d� d@ dA d{ dC dD d& d dE d� dG dA d6 dI dJ d� dL dM d� dO dP d: dR d7 d� dS dL d� d! dU d$ dW d d0 dY d5 d9 dZ d d� d[ d\ d� d] d^ dK d< d_ d� dG dF d� da d3 d; d db d> dc dd d da de dO dg dh d� di d d� d
d d9 dl d d� dm dn d� do d d� dq dr d8 ds dt dw dj dv d� dx dy d� dC dv d� d{ d3 d� d| d} d� dV d| d� d7 d� d� d7 d� dl d� d� d� dj d� d� dU d� d dh d? d� d+ dO d� d� d d dr d d� d� d� df d� d� d	 d d dr ds di d d' dh d� d� dF d� d* d) dI d� d� d5 d� d� d_ d� d" d� d d@ dc d� d d  d- dV d� d� d� dw dL d� d� d- d� d  d d� d� d d d dx d� d� d dA d> d d� dv d� dG d� d d dx d d d� d d� d� d  dy d� d d# d� d$ d% d� d
 d& d d d( d� d) d* d� d+ d, d6 d d& d� d/ d dB d1 d2 d� d4 d5 d" d7 d
dB d d4 d� d: d; dj d< d= d� d d> d d@ dA d dC dD d� d dE d� dG dA d^ dI dJ d� dL dM d� dO dP d� dR d7 dX dS dL d� d! dU d) dW d d� dY d5 d dZ d dx d[ d\ d d] d^ d@ d< d_ d� dG dF d_ da d3 d� d db d� dc dd d� da de d~ dg dh d� di d d- d
d d+ dl d d� dm dn d� do d d� dq dr d� ds dt do dj dv d� dx dy d/ dC dv d� d{ d3 d d| d} dM dV d| d� d7 d� d� d7 d� d� d� d� d� dj d� d� dU d� d dh d? dF d+ dO d� d� d d� dr d d d� d� d� d� d� d� d d d- ds di dk d' dh d� d� dF d� d* d) d= d� d� d+ d� d� d  d� d" dN d d@ d� d� d d� d- dV dJ d� d� d	 dL d� d� d- d� d d d� d d d d dx d� d� d dA d� d d� d� d� dG d� d d d� d d dG d d� d d  dy dI d d# dk d$ d% dp d
 d& d� d d( d d) d* d� d+ d, d� d d& dr d/ d d� d1 d2 d| d4 d5 d� d7 d
d� d d4 dK d: d; d� d< d= dJ d d> d� d@ dA d� dC dD d` d dE d8 dG dA d� dI dJ d dL dM d dO dP d� dR d7 d� dS dL da d! dU d� dW d d dY d5 d1 dZ d dL d[ d\ d� d] d^ d� d< d_ d� dG dF dD da d3 d� d db d� dc dd d� da de d� dg dh d� di d dr d
d dv dl d d@ dm dn d� do d d� dq dr dG ds dt d� dj dv d/ dx dy d� dC dv d4 d{ d3 d� d| d} d  dV d| d� d7 d� d� d7 d� d� d� d� d# dj d� dy dU d� d� dh d? d� d+ dO d~ d� d d dr d d| d� d� d� d� d� d� d d d ds di d� d' dh d d� dF dA d* d) dB d� d� d d� d� d d� d" d d d@ d d� d d< d- dV d� d� d� dT dL d� d� d- d� d3 d d� d� d d d� dx d� d� d dA d� d d� d� d� dG d� d d d� d d d� d d� dr d  dy d� d d# d� d$ d% d� d
 d& dn d d( d� d) d* dO d+ d, d� d d& dG d/ d d� d1 d2 d% d4 d5 d" d7 d
d d d4 d� d: d; d� d< d= d� d d> d� d@ dA d{ dC dD d& d dE d� dG dA d6 dI dJ d� dL dM da dO dP d: dR d7 d� dS dL d� d! dU d� dW d d0 dY d5 d9 dZ d dW d[ d\ d� d] d^ dC d< d_ d� dG dF d� da d3 dk d db d| dc dd dl da de dO dg dh d� di d d� d
d d� dl d d� dm dn d� do d d� dq dr do ds dt d� dj dv dX dx dy d� dC dv d� d{ d3 d� d| d} d dV d| d� d7 d� d� d7 d� d� d� d� d� dj d� d� dU d� d dh d? d d+ dO d d� d dS dr d d d� d� d� d� d� dL d d d ds di d d' dh d^ d� dF d� d* d) d� d� d� dm d� d� d d� d" dz d d@ d� d� d d� d- dV d8 d� d� du dL d� d� d- d� d  d d� d� d d d: dx d� dG d dA d� d d� d� d� dG dK d d d< d d d d d� dQ d  dy d� d d# d~ d$ d% dX d
 d& d d d( dA d) d* dE d+ d, db d d& d{ d/ d d� d1 d2 d� d4 d5 d� d7 d
d� d d4 d� d: d; d� d< d= dM d d> d
d@ dA d� dC dD d� d dE d� dG dA d^ dI dJ d� dL dM dI dO dP d8 dR d7 d� dS dL d� d! dU d dW d dt dY d5 d� dZ d d� d[ d\ d� d] d^ d� d< d_ d
dG dF d_ da d3 d= d db d� dc dd d� da de d� dg dh dQ di d d� d
d d� dl d d� dm dn d� do d d� dq dr d� ds dt do dj dv d� dx dy d� dC dv da d{ d3 dY d| d} de dV d| d� d7 d� d� d7 d� d� d� d� d� dj d� d� dU d� dv dh d? d� d+ dO dF d� d dm dr d d[ d� d� d� d� d� d� d d dG ds di d
 d' dh d� d� dF d� d* d) d� d� d� d d� d� d@ d� d" dn d d@ d� d� d d� d- dV dJ d� d� d	 dL d� d� d- d� d d d� d d d d dx d� d� d dA d� d d� d� d� dG d� d d d� d d d� d d� d� d  dy d d d# d� d$ d% d� d
 d& d3 d d( da d) d* d# d+ d, d� d d& dt d/ d d� d1 d2 d7 d4 d5 dY d7 d
d� d d4 d` d: d; d� d< d= d� d d> d d@ dA d� dC dD d� d dE d� dG dA d� dI dJ d@ dL dM d dO dP d� dR d7 d dS dL d� d! dU dY dW d d� dY d5 d� dZ d dm d[ d\ d� d] d^ dv d< d_ dL dG dF d/ da d3 d d db d dc dd d^ da de d� dg dh dv di d d� d
d d^ dl d de dm dn dM do d d^ dq dr d ds dt d: dj dv d, dx dy d� dC dv d� d{ d3 d� d| d} d, dV d| d� d7 d� d� d7 d� d� d� d� d� dj d� d dU d� d� dh d? d� d+ dO d~ d� d d� dr d dy d� d� d� d� d� dA d d d� ds di d� d' dh d� d� dF d� d* d) d d� d� d} d� d� d d� d" d� d d@ d d� d d� d- dV d� d� d� d2 dL d� d� d- d� d{ d d� d� d d dt dx d� d� d dA d d: d� d� d� dG dM d d d� d d d d d� d� d  dy d d d# d< d$ d% d d
 d& d d d( d� d) d* d� d+ d, d~ d d& d| d/ d d� d1 d2 d d4 d5 d! d7 d
d) d d4 d d: d; d� d< d= d� d d> d� d@ dA d{ dC dD d& d dE d� dG dA d6 dI dJ d� dL dM d� dO dP d! dR d7 dp dS dL d� d! dU d� dW d d: dY d5 d9 dZ d dW d[ d\ d� d] d^ dC d< d_ d� dG dF dA da d3 d^ d db d� dc dd dj da de dO dg dh d� di d d= d
d dE dl d d� dm dn d� do d d: dq dr d� ds dt d	 dj dv d� dx dy dU dC dv d� d{ d3 d� d| d} d� dV d| d� d7 d� d� d7 d� d d� d� d� dj d� d� dU d� d� dh d? d d+ dO d� d� d d� dr d d2 d� d� d� d� d� dL d d de ds di d� d' dh d� d� dF d3 d* d) d� d� d� d� d� d� d� d� d" d1 d d@ d� d� d d d� dV d� d� d� dw dL d� d� d- d� d  d d� d� d d d dx d� d� d dA d> d d� dv d� dG dd d d d d d� d d� d� d  dy d� d d# d! d$ d% d� d
 d& d d d( d� d) d* d� d+ d, d" d d& d� d/ d d d1 d2 d� d4 d5 d� d7 d
d� d d4 d� d: d; d� d< d= d> d d> d d@ dA d dC dD df d dE d� dG dA d^ dI dJ d� dL dM dM dO dP d� dR d7 d3 dS dL d4 d! dU d� dW d dt dY d5 d� dZ d d� d[ d\ d� d] d^ d� d< d_ d
dG dF d_ da d3 d� d db d� dc dd dB d de d~ dg dh d@ di d d� d
d d+ dl d d� dm dn d� do d d� dq dr d� ds dt dY dj dv d� dx dy d/ dC dv da d{ d3 d� d| d} d� dV d| d: d7 d� d� d7 d� d� d� d� d� dj d� d� dU d� dE dh d? d� d+ dO d d� d d� dr d d d� d� dw d� d� d� d d dG ds di dk d' dh d	 d� dF d d* d) du d� d� dY d� d� d� d� d" dE d d@ d� d� d d� d- dV dJ d� d� d	 dL d� d� d- d� d d d� d d d d dx d� d� d dA d� d d� d� d� dG d� d d d� d d dp d d� d� d  dy d� d d# d� d$ d% d� d
 d& d� d d( d� d) d* d� d+ d, d� d d& d� d/ d d� d1 d2 d7 d4 d5 dY d7 d
d� d d4 d� d: d; d� d< d= d� d d> d� d@ dA d� dC dD d1 d dE dS dG dA dp dI dJ d� dL dM d� dO dP dd dR d7 dl dS dL d� d! dU d� dW d d dY d5 d� dZ d dL d[ d\ dp d] d^ d[ d< d_ d� dG dF ds da d3 d� d db d dc dd d da de d� dg dh d� di d d� d
d dv dl d d� dm dn d3 do d dv dq dr d ds dt dW dj dv d- dx dy d� dC dv d� d{ d3 d� d| d} d� dV d| d� d7 d� d� d7 d� d6 d� d� d� dj d� d~ dU d� d� dh d? dD d+ dO d� d� d d dr d d� d� d� d� d� d� d d d d{ ds di dE d' dh d� d� dF d� d* d) d� d� d� d� d� d� d� d� d" d7 d d@ d� d� d d� d- dV d� d� d� d2 dL d� d� d- d� d{ d d� d� d d dt dx d� d� d dA d d: d� d� d� dG dM d d d� d d d d d� dl d  dy d� d d# d& d$ d% d( d
 d& d� d d( d� d) d* d� d+ d, d� d d& d� d/ d d� d1 d2 d
d4 d5 d+ d7 d
d� d d4 d d: d; d� d< d= d d d> d� d@ dA d� dC dD d� d dE dq dG dA d� dI dJ d/ dL dM d� dO dP dg dR d7 d� dS dL d d! dU d dW d d dY d5 d1 dZ d d d[ d\ dz d] d^ d9 d< d_ dL dG dF d� da d3 d� d db d dc dd d! da de d� dg dh d% di d d� d
d d0 dl d d� dm dn dK do d d� dq dr d ds dt d� dj dv d< dx dy d� dC dv d9 d{ d3 dz d| d} dj dV d| d� d7 d� dJ d7 d� di d� d� d& dj d� d dU d� d� dh d? d d+ dO d� d� d d� dr d d� d� d� d� d� d� d� d d d� ds di d  d' dh d� d� dF d� d* d) d� d� d� dZ d� d� d5 d� d" d� d d@ d& d� d d� d- dV d d� d� d dL d� d� d- d� d� d d� d d d d7 dx d� d2 d dA d� d d� d� d� dG d� d d d d d dh d d� d� d  dy du d d# du d$ d% d- d
 d& d^ d d( dX d) d* dI d+ d, d� d d& du d/ d d� d1 d2 d� d4 d5 d� d7 d
d� d d4 dG d: d; d� d< d= d� d d> dX d@ dA d� d� dD d� d dE d� dG dA d� dI dJ d� dL dM dI dO dP d8 dR d7 d� dS dL d� d! dU d dW d dl dY d5 d dZ d d_ d[ d\ d� d] d^ d� d< d_ d� dG dF d+ da d3 d� d db d� dc dd d� da de d dg dh d� di d dK d
d d� dl d d� dm dn d� do d d� dq dr dm ds dt dm dj dv d� dx dy dh dC dv dO d{ d3 d@ d| d} d^ dV d| d� d7 d� d� d7 d� d d� d� d� dj d� dO dU d� d� dh d? d d+ dO d� d� d d� dr d d� d� d� d� d� d� d� d d d] ds di d d' dh d0 d� dF dX d* d) d� d� d� d� d� d� d� d� d" dJ d d@ d� d� d d� d- dV d d� d� d� dL d� d� d- d� dw d d� d� d d d� dx d� dF d dA d� d d� d4 d� dG d� d d d� d d d� d d� d# d  dy d� d d# dW d$ d% d� d
 d& d d d( d d) d* d� d+ d, dF d d& d� d/ d dj d1 d2 d d4 d5 d� d7 d
d d d4 d� d: d; d� d< d= d� d d> d� d@ dA d� dC dD d' d dE d� dG dA d� dI dJ d� dL dM d� dO dP d3 dR d7 d� dS dL dr d! dU dE dW d d� dY d5 d  dZ d d� d[ d\ d� d] d^ dy d< d_ d� dG dF dH da d3 d� d db dH dc dd d� da de d� dg dh de di d d� d
d ds dl d d dm dn d� do d d� dq dr d@ ds dt d� dj dv du dx dy d} dC dv d� d{ d3 d� d| d} d� dV d| d+ d7 d� dk d7 d� d� d� d� d� dj d� d� dU d� d� dh d? d� d+ dO dN d� d d� dr d d� d� d� d< d� d� d
d d d� ds di d� d' dh d, d� dF d� d* d) d� d� d� d3 d� d� d} d� d" d� d d@ d� d� d d� d- dV d� d� d� dy dL d� d d- d� d� d d� d> d d d� dx d� d~ d dA d d d� d� d� dG d/ d d db d d dl d d� d d  dy d� d d# d� d$ d% dh d
 d& d d d( d� d) d* d� d+ d, d� d d& d� d/ d d[ d1 d2 dg d4 d5 d� d7 d
d d d4 d d: d; d� d< d= d` d d> do d@ dA db dC dD dp d dE d$ dG dA d� dI dJ d� dL dM d� dO dP d� dR d7 d
dS dL d� d! dU d� dW d d dY d5 d1 dZ d d d[ d\ dz d] d^ d9 d< d_ dL dG dF d� da d3 d� d db d dc dd d! da de d� dg dh d% di d d� d
d d0 dl d d� dm dn dK do d d� dq dr d ds dt d� dj dv d< dx dy d� dC dv d9 d{ d3 dz d| d} dj dV d| d� d7 d� dJ d7 d� di d� d� d& dj d� d dU d� d� dh d? d d+ dO d� d� d d� dr d d� d� d� d� d� d� d� d d d� ds di d  d' dh d� d� dF d� d* d) d� d� d� dZ d� d� d5 d� d" d� d d@ d& d� d d� d- dV d d� d� d dL d� d� d- d� d� d d� d d d d7 dx d� d2 d dA d� d d� d� d� dG d� d d d d d dh d d� dY d  dy d� d d# ds d$ d% d� d
 d& d d d( d� d) d* d� d+ d, dn d d& d� d/ d dq d1 d2 d� d4 d5 d d7 d
d� d d4 d� d: d; d� d< d= d� d d> d� d@ dA d� dC dD d� d dE d� dG dA d� dI dJ dG dL dM dg dO dP dF dR d7 d� dS dL d@ d! dU d� dW d d� dY d5 d8 dZ d d� d[ d\ d� d] d^ d� d< d_ d� dG dF d+ da d3 d� d db d� dc dd d� da de d dg dh d! di d d d
d d� dl d dE dm dn d do d dc dq dr d� ds dt d8 dj dv dp dx dy db dC dv d� d{ d3 d d| d} d^ dV d| d� d7 d� d{ d� d� d� d� d� d* dj d� d� dU d� dn dh d? d d+ dO d� d� d d/ dr d d d� d� dh d� d� d� d d d� ds di d d' dh d� d� dF d@ d* d) d� d� d� d. d� d� d d� d" d� d d@ d� d� d dk d- dV d0 d� d� d� dL d� d� d- d� d� d d� d� d d d� dx d� d� d dA d� d d� d� d� dG d� d d d� d d dG d d� dH d  dy dI d d# d� d$ d% d� d
 d& d� d d( d2 d) d* d� d+ d, d� d d& d d/ d dw d1 d2 d	 d4 d5 d� d7 d
da d d4 dH d: d; d� d< d= dk d d> d d@ dA d� dC dD d� d dE d� dG dA d` dI dJ d� dL dM d� dO dP dm dR d7 d dS dL dl d! dU dj dW d d� dY d5 d  dZ d d� d[ d\ d� d] d^ d� d< d_ d� dG dF d" da d3 d� d db d� dc dd d da de d� dg dh d di d d� d
d dS dl d d dm dn d� do d d� dq dr d� ds dt d\ dj dv d� dx dy d2 dC dv d� d{ d3 dk d| d} d� dV d| d� d7 d� d� d7 d� d� d� d� d# dj d� dy dU d� d� dh d? d� d+ dO dN d� d d� dr d d� d� d� d� d� d� d d d d- ds di d� d' dh d� d� dF dY d* d) d0 d� d� d} d� d� d d� d" d� d d@ d d� d d� d- dV d� d� d� dy dL d� d d- d� d� d d� d� d d d dx d� d� d dA d� d d� d[ d� dG d d d d� d d d� d d� dl d  dy d� d d# d& d$ d% d( d
 d& d� d d( d4 d) d* d� d+ d, dH d d& dt d/ d dk d� d2 d� d4 d5 d, d7 d
d� d d4 d� d: d; d� d< d= d` d d> do d@ dA db dC dD d� d dE d$ dG dA d� dI dJ dz dL dM d� dO dP d� dR d7 d� dS dL d d! dU d� dW d d� dY d5 d� dZ d d� d[ d\ dp d] d^ dT d< d_ d� dG dF d� da d3 d� d db d dc dd dd da de dG dg dh d di d dH d
d d� dl d dz dm dn d) do d dk dq dr d� ds dt d
dj dv d� dx dy d� dC dv d� d{ d3 dd| d} d� dV d| d� d7 d� dJ d7 d� di d� d� d& dj d� d dU d� d� dh d? d d+ dO d� d� d d� dr d d d� d� d& d� d� d� d d d� ds di d} d' dh d, d� dF dV d* d) dj d� d� dL d� d� d d� d" dz d d@ d� d� d d� d- dV d8 d� d� d dL d� dS d- d� d� d d� d� d d d% dx d� df d dA d� d d� d d� dG d_ d d dm d d d d d� d� d  dy db d d# du d$ d% d- d
 d& dA d d( d� d) d* d� d+ d, d� d d& d� d/ d dY d1 d2 d d4 d5 d� d7 d
dk d d4 d� d: d; d� d< d= d^ d d> d d@ dA d� dC dD d� d dE d dG dA d{ dI dJ d� dL dM d� dO dP dF dR d7 d� dS dL d2 d! dU d� dW d d
 dY d5 d dZ d d_ d[ d\ d� d] d^ d d< d_ d� dG dF d� da d3 do d db d� dc dd d~ da de d dg dh d! di d d d
d d� dl d d� dm dn d do d d� dq dr d� ds dt d� dj dv d
 dx dy df dC dv dz d{ d3 d7 d| d} dE dV d| df d7 d� d� d7 d� d� d� d� d� dj d� d� dU d� d� dh d? d d+ dO d� d� d d� dr d dJ d8 d� d� d� d� d� d d d; ds di d� d' dh dF d� dF dU d* d) dr d� d� d9 d� d� d� d� d" d� d d@ d� d� d d� d- dV d0 d� d� d� dL d� d� d- d� d� d d� d� d d d� dx d� d� d dA d� d d� dX d� dG d� d d d� d d d� d d� d d  dy d d d# d� d$ d% d� d
 d& d d d( dX d) d* d� d+ d, d� d d& d� d/ d d� d1 d2 d| d4 d5 d� d7 d
d� d d4 dK d: d; d� d< d= d� d d> d� d@ dA d� dC dD d9 d dE dP dG dA d` dI dJ d� dL dM d� dO dP dm dR d7 d dS dL dl d! dU dj dW d d� dY d5 d  dZ d d� d[ d\ d� d] d^ d' d< d_ d[ dG dF d� da d3 d� d db d� dc dd d da de dt dg dh d� di d d� d
d d	 dl d d dm dn d do d d� dq dr d' ds dt d> dj dv d� dx dy d� dC dv d� d{ d3 d> d| d} d� dV d| dJ d7 d� dP d7 d� d� d� d� d� dj d� d� dU d� dL dh d? d� d+ dO d< d� d d� dr d d� d� d� d� d� d� d� d d d@ ds di df d' dh d� d� dF d� d* d) d� d� d� d� d� d� d� d� d" d� d d@ d� d� d d, d- dV d� d� d� d$ dL d� d� d- d� d� d d� dI d d d� dx d� d� d dA d� d d� dL d� dG d� d d d� d d d= d d� d) d  dy d� d d# d� d$ d% d� d
 d& d� d d( d4 d) d* d� d+ d, dH d d& d+ d/ d d d1 d2 d� d4 d5 d# d7 d
d< d d4 d� d: d; d� d< d= dE d d> d� d@ dA dV dC dD d d dE d dG dA dj dI dJ d� dL dM d dO dP d! dR d7 dp dS dL d d! dU d� dW d d: dY d5 d dZ d dz d[ d\ d� d] d^ d� d< d_ d� dG dF d� da d3 dN d db d dc dd d! da de d� dg dh d% di d d� d
d d0 dl d d� dm dn d� do d d� dq dr dW ds dt d� dj dv d� dx dy d� dC dv d( d{ d3 d� d| d} d� dV d| d| d7 d� d� d7 d� d d� d� d� dj d� dj dU d� d� dh d? d d+ dO d� d� d d dr d d� d� d� df d� d� d� d d dr ds di d d' dh d, d� dF d` d* d) du d� d� di d� d� d� d� d" d� d d@ d& d� d d� d- dV d d� d� d dL d� d� d- d� d� d d� d5 d d d� dx d� d� d dA d� d d� d d� dG d� d d d� d d d� d d� d� d  dy d� d d# df d$ d% d- d
 d& d^ d d( dX d) d* dI d+ d, d, d d& du d/ d d� d1 d2 d� d4 d5 da d7 d
d� d d4 d� d: d; d8 d< d= d~ d d> d d@ dA dR dC dD d� d dE d� dG dA d dI dJ dL dL dM d� dO dP d' dR d7 d� dS dL d d! dU dU dW d d� dY d5 d� dZ d d� d[ d\ d d] d^ d� d< d_ d9 dG dF dR da d3 dj d db d� dc dd d� da de dB dg dh d� di d dK d
d d� dl d d� dm dn d� do d d� dq dr d� ds dt d� dj dv d
 dx dy df dC dv dz d{ d3 d7 d| d} dE dV d| dV d7 d� d{ d� d� d� d� d� d* dj d� d dU d� dn dh d? d d+ dO d� d� d d� dr d d� d� d� d� d� d� d� d d dn ds di d$ d' dh d� d� dF d� d* d) d� d� d� d� d� d� dR d� d" d� d d@ d� d� d dA d- dV dm d� d� d� dL d� d� d- d� dw d d� d� d d d� dx d� d� d dA d� d d� d� d� dG d� d d d� d d dG d d� dH d  dy dI d d# d� d$ d% d� d
 d& d3 d d( da d) d* d# d+ d, d� d d& dt d/ d dj d1 d2 d	 d4 d5 d� d7 d
de d d4 d d: d; d� d< d= d( d d> d� d@ dA d� dC dD d� d dE d� dG dA d� dI dJ d dL dM d dO dP d� dR d7 d� dS dL dr d! dU dE dW d d� dY d5 d  dZ d d� d[ d\ d� d] d^ d� d< d_ d� dG dF d" da d3 d� d db d� dc dd d da de d� dg dh d di d d� d
d dS dl d d dm dn d� do d d� dq dr d@ ds dt d� dj dv du dx dy d dC dv dZ d{ d3 dT d| d} d dV d| df d7 d� dn d7 d� de d� d� d_ dj d� d� dU d� d� dh d? dG d+ dO d� d� d d� dr d d� d� d� d< d� d� d
d d d� ds di d� d' dh d� d� dF d� d* d) d� d� d� d� d� d� d� d� d" d� d d@ d� d� d d� d- dV de d� d� d� dL d� d� d- d� d� d d� d> d d d� dx d� d~ d dA d d d� d� d� dG d� d d d� d d d� d d� dr d  dy d� d d# d� d$ d% d� d
 d& d� d d( d d) d* d[ d+ d, d� d d& dt d/ d dk d� d2 d� d4 d5 d� d7 d
d� d d4 dG d: d; d� d< d= d` d d> do d@ dA db dC dD dp d dE d$ dG dA d� dI dJ d� dL dM d� dO dP d� dR d7 d
dS dL d� d! dU d� dW d d dY d5 d1 dZ d d d[ d\ dz d] d^ d9 d< d_ d� dG dF d� da d3 dk d db d| dc dd dl da de dZ dg dh d� di d dC d
d dX dl d d� dm dn dl do d dn dq dr d~ ds dt d� dj dv d< dx dy d� dC dv d� d{ d3 dz d| d} dc dV d| d� d7 d� dM d7 d� d� d� d� d} dj d� d� dU d� d� dh d? d d+ dO d d� d dS dr d d� d� d� d� d� d� d� d d d� ds di d  d' dh d� d� dF d� d* d) d� d� d� dZ d� d� d5 d� d" d7 d d@ d� d� d d� d- dV d� d� d� d� dL d� d� d- d� di d d� d� d d d: dx d� dG d dA d� d d� d� d� dG d� d d d d d dk d d� d� d  dy d2 d d# d� d$ d% d� d
 d& d� d d( d� d) d* dE d+ d, db d d& d� d/ d d� d1 d2 d� d4 d5 da d7 d
d� d d4 d� d: d; d� d< d= d� d d> d d@ dA d� dC dD d� d dE d� dG dA d� dI dJ dG dL dM dg dO dP dF dR d7 d� dS dL d@ d! dU d� dW d d� dY d5 d8 dZ d d� d[ d\ d� d] d^ d d< d_ d� dG dF d� da d3 do d db d� dc dd d~ da de d dg dh d! di d d d
d d� dl d d� dm dn d do d d� dq dr dm ds dt d8 dj dv dp dx dy db dC dv d� d{ d3 d d| d} dE dV d| dV d7 d� d{ d� d� d� d� d� d* dj d� d dU d� dn dh d? d d+ dO d� d� d d� dr d dJ d8 d� d� d� d� d� d d d; ds di d� d' dh d� d� dF d@ d* d) d� d� d� d d� d� d d� d" dJ d d@ d� d� d d- d- dV d d� d� d� dL d� d� d- d� d d d� d� d d d� dx d� dF d dA d� d d� d4 d� dG da d d d� d d d� d d� d d  dy d d d# d� d$ d% d� d
 d& d� d d( d} d) d* da d+ d, dn d d& dL d/ d dG d1 d2 d� d4 d5 d� d7 d
d d d4 dm d: d; d* d< d= d� d d> d� d@ dA d
dC dD d� d dE d� dG dA d� dI dJ d� dL dM d� dO dP d3 dR d7 dS dS dL d� d! dU d� dW d d* dY d5 d3 dZ d d� d[ d\ d^ d] d^ dy d< d_ d� dG dF d� da d3 d� d db d? dc dd di da de d dg dh d di d d} d
d dl dl d do dm dn d� do d d� dq dr d� ds dt d� dj dv d� dx dy d= dC dv d� d{ d3 d� d| d} d dV d| dg d7 d� dn d7 d� d� d� d� d dj d� d� dU d� dY dh d? d d+ dO dN d� d d� dr d d� d� d� d� d� d� d d d d- ds di d� d' dh d� d� dF dY d* d) d� d� d� d d� d� d� d� d" d d d@ d� d� d d� d- dV d� d� d� d� dL d� d� d- d� d� d d� d� d d d. dx d� d� d dA d� d d� d; d� dG d� d d d� d d d d d� d� d  dy dD d d# d� d$ d% d; d
 d& d� d d( d� d) d* d� d+ d, d d d& dc d/ d dp d1 d2 dI d4 d5 d� d7 d
dE d d4 dL d: d; dF d< d= d� d d> d� d@ dA dp dC dD d d dE dX dG dA d� dI dJ d� dL dM d dO dP d! dR d7 dp dS dL d d! dU d� dW d d: dY d5 d dZ d dz d[ d\ d� d] d^ d� d< d_ d� dG dF d� da d3 dN d db d dc dd d! da de d� dg dh d� di d d� d
d d� dl d d� dm dn d) do d dk dq dr d ds dt dG dj dv d� dx dy d� dC dv d^ d{ d3 dz d| d} dj dV d| d� d7 d� dJ d7 d� di d� d� d& dj d� d dU d� d� dh d? d d+ dO d d� d dS dr d d� d� d� d� d� d� d
 d d d) ds di d d' dh d� d� dF d� d* d) d d� d� d� d� d� d_ d� d" d� d d@ d& d� d d� d- dV d d� d� d� dL d� d� d- d� d4 d d� d� d d d� dx d� d� d dA d� d d� d d� dG d_ d d dm d d d d d� d� d  dy db d d# du d$ d% d- d
 d& d^ d d( d� d) d* d' d+ d, d d d& d d/ d df d1 d2 d d4 d5 dY d7 d
d� d d4 d� d: d; dQ d< d= d� d d> d. d@ dA d� dC dD d
 d dE d� dG dA d dI dJ d� dL dM d� dO dP d; dR d7 d� dS dL d@ d! dU d� dW d d� dY d5 d� dZ d d� d[ d\ d[ d] d^ d� d< d_ d9 dG dF dR da d3 dj d db d� dc dd d� da de dB dg dh d� di d dK d
d d� dl d d� dm dn d� do d d� dq dr d ds dt d� dj dv d� dx dy dS dC dv d� d{ d3 d7 d| d} d� dV d| d
 d7 d� d� d7 d� d4 d� d� d� dj d� dO dU d� d� dh d? d d+ dO d� d� d d� dr d dJ d8 d� d� d� d� d� d d d; ds di d� d' dh d� d� dF d@ d* d) d� d� d� d d� d� d d� d" dJ d d@ d� d� d d� d- dV dY d� d� d dL d� dA d- d� d< d d� d� d d dA dx d� d! d dA d d d� d� d� dG d� d d dI d d d� d d� d d  dy d d d# d� d$ d% d� d
 d& d� d d( d} d) d* d� d+ d, dF d d& d� d/ d dj d1 d2 d	 d4 d5 d� d7 d
da d d4 dH d: d; d� d< d= d� d d> d� d@ dA d dC dD d� d dE dn dG dA d� dI dJ dw dL dM d dO dP d� dR d7 d� dS dL dr d! dU dE dW d d� dY d5 d  dZ d d� d[ d\ d� d] d^ dy d< d_ d� dG dF dH da d3 d� d db dH dc dd d� da de d� dg dh de di d d� d
d ds dl d d dm dn d� do d d� dq dr d@ ds dt d� dj dv du dx dy d} dC dv d� d{ d3 d� d| d} d� dV d| d+ d7 d� dk d7 d� d� d� d� d� dj d� d� dU d� d� dh d? d� d+ dO dN d� d d� dr d d� d� d� d< d� d� d
d d d� ds di d� d' dh d, d� dF d� d* d) d� d� d� d d� d� d
d� d" d� d d@ d� d� d d, d- dV d d� d� d� dL d� d0 d- d� d� d d� dG d d d1 dx d� di d dA d� d d� d	 d� dG d� d d d d d d d d� d� d  dy d� d d# dm d$ d% d~ d
 d& dz d d( d d) d* dO d+ d, dY d d& d� d/ d d� d1 d2 d d4 d5 d d7 d
d d d4 d� d: d; d� d< d= d� d d> d� d@ dA d{ dC dD d& d dE d� dG dA d6 dI dJ d� dL dM d� dO dP d: dR d7 d� dS dL d� d! dU d� dW d d0 dY d5 d9 dZ d dW d[ d\ d� d] d^ dC d< d_ d� dG dF dA da d3 d^ d db d� dc dd dj da de dO dg dh d� di d d� d
d d� dl d d� dm dn d� do d d� dq dr d� ds dt d� dj dv d� dx dy d| dC dv d� d{ d3 d� d| d} d dV d| d& d7 d� d� d7 d� do d� d� dZ dj d� d� dU d� d dh d? d d+ dO d� d� d d� dr d d2 d� d� d� d� d� dL d d d ds di d d' dh d� d� dF d3 d* d) d� d� d� dX d� d� di dY d" d d d@ dc d� d d  d- dV d� d� d� dw dL d� d� d- d� d  d d� d� d d d dx d� d� d dA d> d d� dv d� dG d� d d d d d dn d d� d� d  dy d� d d# d! d$ d% d� d
 d& d� d d( d� d) d* d� d+ d, d� d d& d d/ d dB d1 d2 d[ d4 d5 d� d7 d
dM d d4 d d: d; d� d< d= d> d d> d d@ dA d dC dD d� d dE d� dG dA d� dI dJ d� dL dM dM dO dP d� dR d7 d� dS dL d� d! dU d% dW d dt dY d5 d� dZ d d� d[ d\ dd d] d^ d d< d_ d
dG dF d� da d3 d� d db d� dc dd dy da de d~ dg dh d� di d d+ d
d d� dl d d� dm dn dH do d d� dq dr d" ds dt dY dj dv d� dx dy d� dC dv dF d{ d3 dJ d| d} de dV d| d� d7 d� dC d7 d� d� d� d� d dj d� d� dU d� dK dh d? d� d+ dO d� d� d d� dr d dr d� d� d- d� d� d� d d d� ds di dk d' dh dQ d� dF d� d* d) d� d� d� d! d� d� d@ d� d" d� d d@ d� d� d dh d- dV dJ d� d� d� dL d� dM d- d� d d d� d� d d d dx d� d d dA d	 d d� d� d� dG d� d d d d d d� d d� d� d  dy dd d# d� d$ d% d� d
 d& d? d d( d� d) d* d� d+ d, dO d d& d� d/ d d� d1 d2 d7 d4 d5 dl d7 d
d� d d4 d` d: d; d� d< d= d� d d> dg d@ dA d� dC dD dC d dE d] dG dA dq dI dJ dP dL dM d� dO dP d� dR d7 d dS dL d� d! dU d� dW d d� dY d5 d� dZ d d� d[ d\ dp d] d^ d[ d< d_ d� dG dF d/ da d3 d� d db d dc dd d� da de d� dg dh dU di d d� d
d d� dl d d� dm dn d? do d dv dq dr dC ds dt d: dj dv d, dx dy d� dC dv d� d{ d3 d� d| d} d� dV d| d� d7 d� d� d7 d� dO d� d� di dj d� d dU d� d� dh d? d5 d+ dO d  d� d d� dr d d	 d� d� d� d� d� d� d d d� ds di dE d' dh d� d� dF d� d* d) d� d� d� d� d� d� d� d� d" d7 d d@ d� d� d dw d- dV d d� d� d2 dL d� d� d- d� d{ d d� d� d d dt dx d� d$ d dA d� d d� d� d� dG d� d d d� d d d d d� dQ d  dy d� d d# dS d$ d% d> d
 d& dz d d( d d) d* dR d+ d, d� d d& dX d/ d d� d1 d2 d� d4 d5 d+ d7 d
d d d4 d� d: d; d� d< d= d% d d> d� d@ dA d� dC dD d� d dE d dG dA d� dI dJ d9 dL dM d� dO dP dK dR d7 dE dS dL dS d! dU d� dW d d, dY d5 d� dZ d dA d[ d\ dd d] d^ d� d< d_ d= dG dF d da d3 d; d db d� dc dd dI da de dS dg dh d	 di d d< d
d db dl d d� dm dn d� do d d� dq dr d� ds dt d� dj dv d� dx dy d� dC dv d� d{ d3 dd| d} d� dV d| d� d7 d� dd7 d� dW d� d� d� dj d� dA dU d� d� dh d? d� d+ dO dv d� d d< dr d d� d� d� d� d� d� d� d d d� ds di d� d' dh d� d� dF d3 d* d) d� d� d� dX d� d� d+ d� d" d� d d@ dc d� d ds d- dV d� d� d� d� dL d� dd- d� d" d d� d  d d d� dx d� d� d dA d� d d� d� d� dG d[ d d d� d d dY d d� d d  dy d d d# d d$ d% d� d
 d& d d d( d� d) d* d� d+ d, d6 d d& d� d/ d dB d1 d2 d[ d4 d5 d d7 d
d� d d4 d d: d; d� d< d= d� d d> d d@ dA d dC dD ds d dE d> dG dA d^ dI dJ d� dL dM dM dO dP d� dR d7 d3 dS dL d4 d! dU d� dW d dt dY d5 d� dZ d dT d[ d\ d� d] d^ d� d< d_ d� dG dF dr da d3 d\ d db d dc dd dt da de dJ dg dh d� di d d� d
d d� dl d d� dm dn dG do d d� dq dr d� ds dt d� dj dv d3 dx dy d� dC dv d� d{ d3 d d| d} dM dV d| d� d7 d� dC d7 d� d� d� d� dm dj d� d� dU d� dE dh d? d� d+ dO d d� d d� dr d d d� d� dw d� d� d� d d dG ds di dk d' dh d	 d� dF d� d* d) d1 d� d� d� d� d� d� d� d" d� d d@ d� d� d d� d- dV dJ d� d� d	 dL d� d� d- d� d d d� d d d d dx d� d� d dA dP d d� d� d� dG d� d d d� d d d� d d� d9 d  dy d d d# d� d$ d% d� d
 d& d� d d( d� d) d* d� d+ d, d� d d& d� d/ d d� d1 d2 d7 d4 d5 dY d7 d
d� d d4 d` d: d; d� d< d= d� d d> dg d@ dA d� dC dD db d dE d� dG dA d: dI dJ d! dL dM d� dO dP d� dR d7 d) dS dL d� d! dU d6 dW d d� dY d5 d� dZ d dm d[ d\ d� d] d^ dv d< d_ dL dG dF d/ da d3 d d db d dc dd d^ da de d� dg dh ds di d dH d
d dv dl d d� dm dn d? do d d� dq dr d ds dt dW dj dv d- dx dy d� dC dv d� d{ d3 d� d| d} d� dV d| d� d7 d� d8 d7 d� dT d� d� dX dj d� dB dU d� d� dh d? d d+ dO d  d� d d� dr d d� d� d� d� d� d� d" d d d� ds di d� d� dh d� d� dF dc d* d) d d� d� d� d� d� d� d� d" d� d d@ d� d� d d# d- dV d� d� d� d� dL d� d  d- d� d d d� d� d d d/ dx d� d� d dA d� d d� d d� dG d� d d d� d d d� d d� d d  dy d4 d d# d� d$ d% d� d
 d& d� d d( d d) d* d� d+ d, do d d& d� d/ d d� d1 d2 d� d4 d5 d d7 d
d� d d4 d� d: d; dk d< d= d
d d> d d@ dA d	 dC dD d� d dE d� dG dA d= dI dJ d] d� dM d) dO dP d> dR d7 dl dS dL dR d! dU d� dW d d, dY d5 d� dZ d dA d[ d\ dd d] d^ d� d< d_ d= dG dF d da d3 d; d db d� dc dd dI da de dS dg dh d	 di d d< d
d db dl d d� dm dn d� do d d dq dr d� ds dt d� dj dv d� dx dy dA dC dv d� d{ d3 d� d| d} d� dV d| ds d7 d� d? d7 d� dl d� d� d� dj d� d� dU d� d dh d? d� d+ dO d d� d d7 dr d d� d� d� d� d� d� d: d d dD ds di d� d' dh dH d� dF d� d* d) d� d� d� d d� d� d� d� d" d\ d d@ d_ d� d dK d- dV d� d� d� d6 dL d� d� d- d� d  d d� d� d d d dx d� d� d dA d� d d� d� d� dG d d d d� d d d� d d� d d  dy d� d d# dq d$ d% d/ d
 d& d� d d( d� d) d* d� d+ d, d6 d d& d� d/ d dB d1 d2 d d4 d5 d� d7 d
dB d d4 d� d: d; d� d< d= d� d d> d� d@ dA d dC dD d� d dE d� dG dA dG dI dJ d� dL dM d� dO dP d dR d7 dX dS dL d� d! dU d% dW d d" dY d5 d dZ d d
 d[ d\ dd d] d^ dp d< d_ du dG dF d da d3 d� d db d� dc dd dr da de d� dg dh d� di d d- d
d dZ dl d d� dm dn d� do d d� dq dr d ds dt d� dj dv d� dx dy d dC dv d� d{ d3 d d| d} d� dV d| d� d7 d� d� d7 d� d� d� d� d� dj d� d� dU d� d9 dh d? d� d+ dO d� d� d d� dr d dY d� d� d- d� d� d' d d dC ds di d� d' dh dW d� dF d| d* d) d� d� d� dY d� d� d� d� d" dU d d@ d> d� d d d- dV d[ d� d� d  dL d� d` d- d� d? d d� d� d d ds dx d� d� d dA dY d d� d d� dG d� d d d� d d d� d d� dh d  dy d� d d# dk d$ d% d? d
 d& d� d d( d� d) d* d� d+ d, dS d d& d� d/ d d� d1 d2 d7 d4 d5 d: d7 d
d d d4 d� d: d; d� d< d= d� d d> d� d@ dA d� dC dD d� d dE d� dG dA d: dI dJ d dL dM d� dO dP d� dR d7 d� dS dL dm d! dU d� dW d d� dY d5 d: dZ d d� d[ d\ dp d] d^ d� d< d_ dG dG dF d� da d3 d� d db dm dc dd d� da de d� dg dh ds di d dH d
d d� dl d d- dm dn d� do d d� dq dr d� ds dt d: dj dv d� dx dy d� dC dv d� d{ d3 d� d| d} dr dV d| d
 d7 d� d4 d7 d� d� d� d� d� dj d� d� dU d� d~ dh d? d� d+ dO d� d� d d� dr d d� d� d� dX d� d� d� d d d� ds di d� d' dh d� d� dF d d* d) d� d� d� d d� d� dH d� d" d_ d d@ d) d� d d� d- dV dd� d� d� dL d� d� d- d� dE d d� d� d d d� dx d� dP d dA d� d d� d d� dG d� d d d� d d dU d d� d d  dy d] d d# dm d$ d% dS d
 d& d d d( dC d) d* d d+ d, d� d d& dC d/ d d d1 d2 d# d4 d5 d d7 d
d� d d4 dw d: d; d� d< d= d d d> d d@ dA d` dC dD d" d dE d� dG dA d= dI dJ dY dL dM d� dO dP d� dR d7 dl dS dL d� d! dU d4 dW d d� dY d5 d� dZ d d� d[ d\ d d] d^ dK d< d_ d= dG dF dT da d3 d� d db d> dc dd d� da de db dg dh d� di d d� d
d d� dl d d' dm dn d� do d d dq dr d ds dt d� dj dv d� dx dy d� dC dv d� d{ d3 d� d| d} d� dV d| d d7 d� d? d7 d� d� d� d� d� dj d� d� dU d� d dh d? d# d+ dO d d� d d� d� d d� d� d� d� d� d� d� d d d� ds di d d' dh d� d� dF d3 d* d) d� d� d� d d� d� d� d� d" d d d@ db d� d d� d- dV d� d� d� dH dL d� d� d- d� d� d d� d5 d d d� dx d� dX d dA d� d d� dv d� dG dd d d d d d� d d� d� d  dy d� d d# d! d$ d% d/ d
 d& d� d d( d� d) d* d� d+ d, dq d d& dg d/ d dl d1 d2 d d4 d5 d� d7 d
d� d d4 d� d: d; d� d< d= d� d d> d� d@ dA d dC dD d� d dE d� dG dA dG dI dJ d� dL dM d� dO dP d dR d7 dX dS dL d� d! dU d% dW d d" dY d5 d dZ d d
 d[ d\ dd d] d^ dp d< d_ du dG dF d da d3 d� d db d� dc dd dr da de d� dg dh d� di d d- d
d dZ dl d d� dm dn d� do d d� dq dr d ds dt d� dj dv d� dx dy d dC dv d� d{ d3 d d| d} d� dV d| d� d7 d� d� d7 d� d� d� d� d� dj d� d� dU d� d9 dh d? d� d+ dO d� d� d d� dr d d� d� d� d� d� d� d� d d d� ds di d� d' dh d	 d� dF d d* d) dP d� d� dv d� d� d� d� d" d� d d@ d` d� d d� d- dV dR d� d� dI dL d� d� d- d� dB d d� de d d d� dx d� d� d dA d� d d� dU d� dG d$ d d d d d d d d� d1 d  dy d} d d# d� d$ d% d� d
 d& d� d d( d� d) d* d_ d+ d, d� d d& d� d/ d d� d1 d2 d� d4 d5 d| d7 d
d� d d4 d` d: d; d� d< d= d� d d> d� d@ dA d� dC dD d� d dE d� dG dA d: dI dJ d dL dM d� dO dP d� dR d7 d� dS dL dm d! dU d� dW d d� dY d5 d: dZ d d� d[ d\ dp d] d^ d� d< d_ dG dG dF d� da d3 d� d db dm dc dd d� da de d� dg dh ds di d dH d
d d� dl d d- dm dn d� do d d� dq dr d� ds dt d: dj dv d� dx dy d� dC dv d� d{ d3 d� d| d} dr dV d| d
 d7 d� d4 d7 d� d� d� d� d� dj d� d� dU d� d~ dh d? d� d+ dO d� d� d d� dr d d� d� d� d� d� d� d d d d- ds di d� d' dh d� d� dF d� d* d) d� d� d� d& d� d� d\ d� d" d% d d@ d6 d� d d< d- dV d� d� d� d� dL d� d] d- d� d3 d d� d d d dt dx d� d� d dA d d: d� d� d� dG dM d d d� d d d d d� d� d  dy d� d d# d� d$ d% dS d
 d& d d d( d� d) d* d� d+ d, d� d d& dC d/ d d d1 d2 d� d4 d5 dv d7 d
d� d d4 d� d: d; d� d< d= d d d> d d@ dA d` dC dD d" d dE d� dG dA d= dI dJ dY dL dM d� dO dP d� dR d7 dl dS dL d� d! dU d4 dW d d� dY d5 d� dZ d d� d[ d\ d d] d^ dK d< d_ d= dG dF dT da d3 d� d db d> dc dd d� da de db dg dh d� di d d� d
d d� dl d d' dm dn d� do d d dq dr d ds dt d� dj dv d� dx dy d� dC dv d� d{ d3 d� d| d} d� dV d| d d7 d� d? d7 d� d� d� d� d� dj d� d� dU d� d dh d? d# d+ dO d d� d d� d� d d� d� d� d� d� d� d� d d d� ds di d d' dh d� d� dF d3 d* d) d_ d� d� dX d� d� di dY d" d� d d@ db d� d d� d- dV d� d� d� dH dL d� dD d- d� d� d d� d5 d d d� dx d� dX d dA d� d d� dv d� dG d d d d� d d d� d d� d d  dy d� d d# d! d$ d% d d
 d& d d d( d� d) d* d6 d+ d, dq d d& dg d/ d dl d1 d2 d d4 d5 ds d7 d
d� d d4 d� d: d; d� d< d= d� d d> d� d@ dA d dC dD d� d dE d� dG dA dG dI dJ d� dL dM d� dO dP d dR d7 dX dS dL d� d! dU d% dW d d" dY d5 d dZ d d
 d[ d\ dd d] d^ dp d< d_ du dG dF d da d3 d� d db d� dc dd dr da de d� dg dh d� di d d- d
d dZ dl d d� dm dn d� do d d� dq dr d ds dt d� dj dv d� dx dy d dC dv d� d{ d3 d d| d} d� dV d| d� d7 d� d� d7 d� d� d� d� d� dj d� d� dU d� d9 dh d? d� d+ dO d� d� d d� dr d dY d� d� d- d� d� d� d d dn ds di d$ d' dh d� d� dF d� d* d) d_ d� d� d! d� d� d� d� d" d� d d@ d� d� d d� d- dV d! d� d� d� dL d� d� d- d� d� d d� d d d d� dx d� d^ d dA d' d d� d� d� dG d� d d d� d d d� d d� dh d  dy d� d d# dk d$ d% d� d
 d& d d d( d[ d) d* d� d+ d, dJ d d& d d/ d d� d1 d2 d" d4 d5 d' d7 d
d� d d4 d` d: d; d� d< d= d� d d> d� d@ dA d� dC dD d� d dE d� dG dA d: dI dJ d dL dM d� dO dP d� dR d7 d� dS dL dm d! dU d� dW d d� dY d5 d: dZ d d� d[ d\ dp d] d^ d� d< d_ dG dG dF d� da d3 d� d db dm dc dd d� da de d� dg dh ds di d dH d
d d� dl d d- dm dn d� do d d� dq dr d� ds dt d: dj dv d� dx dy d� dC dv d� d{ d3 d� d| d} dr dV d| d
 d7 d� d4 d7 d� d� d� d� d� dj d� d� dU d� d~ dh d? d� d+ dO d� d� d d� dr d d� d� d� d� d� d� d� d d d ds di d� d' dh d d� dF d� d* d) d� d� d� d� d� d� d� d� d" dk d d@ d� d� d d� d- dV d d� d� d� dL d� d
 d- d� d9 d d� d� d d d1 dx d� di d dA d� d d� d	 d� dG d� d d d� d d dU d d� d d  dy d] d d# dj d$ d% d d
 d& dV d d( d� d) d* d d+ d, dY d d& d� d/ d dd1 d2 d d4 d5 d� d7 d
d� d d4 dd d: d; d� d< d= d d d> d d@ dA d` dC dD d" d dE d� dG dA d= dI dJ dY dL dM d� dO dP d� dR d7 dl dS dL d� d! dU d4 dW d d� dY d5 d� dZ d d� d[ d\ d d] d^ dK d< d_ d= dG dF dT da d3 d� d db d> dc dd d� da de db dg dh d� di d d� d
d d� dl d d' dm dn d� do d d dq dr d ds dt d� dj dv d� dx dy d� dC dv d� d{ d3 d� d| d} d� dV d| d d7 d� d? d7 d� d� d� d� d� dj d� d� dU d� d dh d? d d+ dO d� d� d d� dr d d2 d� d� d� d� d� d� d d d� ds di d d' dh d� d� dF d� d* d) d� d� d� dM d� d� d� d� d" d7 d d@ d� d� d d� d- dV d d� d� d� dL d� d� d- d� dq d d� d  d d dh dx d� d� d dA d> d d� d� d� dG dj d d d� d d d� d d� d� d  dy d� d d# dC d$ d% d� d
 d& d> d d( d� d) d* d� d+ d, dv d d& d� d/ d dB d1 d2 d� d4 d5 d� d7 d
de d d4 d� d: d; d� d< d= d> d d> d� d@ dA d dC dD d� d dE d� dG dA dG dI dJ d� dL dM d� dO dP d dR d7 dX dS dL d� d! dU d% dW d d" dY d5 d dZ d d
 d[ d\ dd d] d^ dp d< d_ du dG dF d da d3 d� d db d� dc dd dr da de d� dg dh d� di d d- d
d dZ dl d d� dm dn d� do d d� dq dr d ds dt d� dj dv d� dx dy d dC dv d� d{ d3 d d| d} d� dV d| d� d7 d� d� d7 d� d� d� d� d� dj d� d� dU d� d- dh d? d� d+ dO dx d� d d� dr d dY d� d� d� d� d� d� d d dk ds di d� d' dh d� d� dF d� d* d) d� d� d� d� d� d� dR d� d" d� d d@ d� d� d d% d- dV dm d� d� d	 dL d� dM d- d� d� d d� dK d d d dx d� d� d dA dP d d� d� d� dG d$ d d d d d d� dZ d� d� d  dy dw d d# d% d$ d% d� d
 d& di d d( d� d) d* d� d+ d, dD d d& dG d/ d d� d1 d2 d7 d4 d5 d� d7 d
d� d d4 d d: d; d" d< d= dm d d> d� d@ dA d� dC dD d� d dE d� dG dA d: dI dJ d dL dM d� dO dP d� dR d7 d� dS dL dm d! dU d� dW d d� dY d5 d: dZ d d� d[ d\ dp d] d^ d� d< d_ dG dG dF d� da d3 d� d db dm dc dd d� da de d� dg dh ds di d dH d
d d� dl d d- dm dn d� do d d� dq dr d� ds dt d: dj dv d� dx dy d� dC dv d� d{ d3 d� d| d} dr dV d| d
 d7 d� d4 d7 d� d� d� d� d_ dj d� d� dU d� d� dh d? d� d+ dO d� d� d d� dr d d d� d� d� d� d� d^ d d d� ds di d9 d' dh d6 d� dF d8 d* d) dA d� d� d} d� d� d d� d" d� d d@ d d� d d� d- dV d� d� d� db dL d� d� d- d� d� d d� d� d d d" dx d� d� d dA d d d� ds d� dG d� d d dq d d d� d d� dE d  dy d� d d# d� d$ d% d� d
 d& d d d( dP d) d* dR d+ d, d� d d& d� d/ d d� d1 d2 d� d4 d5 d d7 d
d d d4 d� d: d; dB d< d= d/ d d> d� d@ dA d{ dC dD d& d dE d� dG dA d6 dI dJ dY dL dM d� dO dP d� dR d7 dl dS dL d� d! dU d4 dW d d� dY d5 d� dZ d d� d[ d\ d d] d^ dK d< d_ d= dG dF dT da d3 d� d db d> dc dd d� da de db dg dh d� di d d� d
d d� dl d d' dm dn d� do d d dq dr d ds dt d� dj dv d� dx dy d� dC dv d� d{ d3 d� d| d} d� dV d| d d7 d� dG d7 d� d~ d� d� d� dj d� d. dU d� d� dh d? d| d+ dO d d� d d� dr d d� d� d� d� d� d� d$ d d d� ds di d� d' dh d� d� dF d� d* d) d� d� d� d� d� d� d� d� d" d1 d d@ d� d� d d  d- dV d� d� d� dw dL d� d� d- d� d  d d� d� d d d dx d� d d dA d d d� d d� dG d� d d dg d d d� d d� d! d  dy d� d d# d� d$ d% du d
 d& d! d d( d� d) d* dr d+ d, dv d d& d� d/ d d d1 d2 d d4 d5 d� d7 d
d� d d4 d� d: d; d� d< d= d d d> d d@ dA dz dC dD d� d dE dU dG dA d dI dJ d� dL dM d� dO dP d dR d7 dX dS dL d� d! dU d% dW d d" dY d5 d dZ d d
 d[ d\ dd d] d^ dp d< d_ du dG dF d da d3 d� d db d� dc dd dr da de d� dg dh d� di d d- d
d dZ dl d d� dm dn d� do d d� dq dr d ds dt d� dj dv d� dx dy d dC dv d� d{ d3 d d| d} d� dV d| d� d7 d� d{ d� d� d� d� d� d* dj d� d� dU d� dn dh d? d� d+ dO d� d� d d� dr d d� d� d� d� d� d� d d d d� ds di d1 d' dh d� d� dF dL d* d) dP d� d� dv d� d� dM d� d" dU d d@ d> d� d d� d- dV dR d� d� dI dL d� d� d- d� d� d d� d� d d dF dx d� d� d dA d� d d� d d� dG dA d d d+ d d d� d d� d� d  dy d[ d d# d� d$ d% d= d
 d& d� d d( d� d) d* d� d+ d, dD d d& dG d/ d d� d1 d2 df d4 d5 d: d7 d
d d d4 d` d: d; d0 d< d= d� d d> dd d@ dA d� dC dD d� d dE d dG dA dC dI dJ dT dL dM d� dO dP d� dR d7 d� dS dL dm d! dU d� dW d d� dY d5 d: dZ d d� d[ d\ dp d] d^ d� d< d_ dG dG dF d� da d3 d� d db dm dc dd d� da de d� dg dh ds di d dH d
d d� dl d d- dm dn d� do d d� dq dr d� ds dt d: dj dv d� dx dy d� dC dv d� d{ d3 d� d| d} dr dV d| dS d7 d� d� d7 d� d6 d� d� d� dj d� d dU d� d� dh d? d! d+ dO d  d� d d� dr d d� d� d� d� d� d� d d d d� ds di d� d' dh d� d� dF d� d* d) d� d� d� d� d� d� d� d� d" d7 d d@ d� d� d d� d- dV d� d� d� d2 dL d� d� d- d� d{ d d� d� d d d� dx d� d� d dA d� d d� d; d� dG d� d d d� d d d d d� d� d  dy d d d# d� d$ d% d� d
 d& do d d( d� d) d* d  d+ d, d� d d& d d/ d d� d1 d2 d d4 d5 d� d7 d
d d d4 d� d: d; d� d< d= d� d d> d� d@ dA d dC dD da d dE d� dG dA d� dI dJ d+ dL dM d� dO dP d: dR d7 dt dS dL d� d! dU dl dW d d� dY d5 d� dZ d d� d[ d\ dd] d^ d d< d_ d� dG dF dA da d3 d; d db d> dc dd d da de d� dg dh d	 di d d= d
d dD dl d dx dm dn d� do d d� dq dr d8 ds dt d� dj dv d� dx dy dA dC dv d� d{ d3 d� d| d} d� dV d| ds d7 d� d? d7 d� dl d� d� d� dj d� d� dU d� d dh d? d� d+ dO d d� d d7 dr d d� d� d� d� d� d� d� d d d� ds di d� d' dh d� d� dF d� d* d) d� d� d� d� d� d� di dY d" d d d@ d� d� d d� d- dV d� d� d� dH dL d� d d- d� d d d� d� d d d: dx d� dX d dA d� d d� d� d� dG dd d d� d d d� d d� dZ d  dy d� d d# d@ d$ d% d� d
 d& d� d d( d� d) d* d� d+ d, dM d d& dg d/ d dl d1 d2 d d4 d5 dS d7 d
dh d d4 dt d: d; d d< d= dW d d> d� d@ dA d9 dC dD d� d dE d^ dG dA d� dI dJ d* dL dM d� dO dP d� dR d7 d� dS dL d� d! dU d dW d d] dY d5 d� dZ d d0 d[ d\ d; d] d^ d~ d< d_ dZ dG dF d� da d3 d� d db d� dc dd dy da de d3 dg dh d> di d ds d
d d� dl d d� dm dn d� do d d� dq dr dS ds dt do dj dv d� dx dy d dC dv da d{ d3 dY d| d} d� dV d| d� d7 d� d� d7 d� d� d� d� d� dj d� d� dU d� d9 dh d? d� d+ dO d� d� d d] dr d dY d� d� d� d� d� d' d d dG ds di d
 d' dh d� d� dF d� d* d) d( d� d� d d� d� d� d� d" dn d d@ d� d� d d� d- dV d! d� d� d� dL d� dC d- d� d� d d� dU d d dA dx d� d! d dA d' d d� d� d� dG d� d d d� d d d� d d� d� d  dy d� d d# d� d$ d% d? d
 d& d� d d( d d) d* d� d+ d, d� d d& d� d/ d d� d1 d2 d� d4 d5 d d7 d
dg d d4 dv d: d; d� d< d= dJ d d> dz d@ dA d� dC dD d� d dE dS dG dA dp dI dJ d� dL dM d� dO dP dE dR d7 d dS dL d� d! dU d� dW d d dY d5 d dZ d d d[ d\ d d] d^ d� d< d_ d& dG dF d2 da d3 d d db dm dc dd d� da de d� dg dh d� di d d8 d d d dl d d� dm dn d# do d dS dq dr d ds dt dZ dj dv d� dx dy d> dC dv d� d{ d3 d� d| d} d� dV d| d� d7 d� d4 d7 d� d� d� d� d� dj d� d dU d� d~ dh d? d� d+ dO d� d� d d dr d d� d� d� d� d� d� d� d d d{ ds di d� d' dh d� d� dF d� d* d) d� d� d� d� d� d� d d� d" d� d d@ d� d� d d� d- dV d� d� d� dA dL d� d� d- d� d� d d� d� d d d5 dx d� dv d dA d� d d� d	 d� dG d� d d dN d d d d d� d� d  dy d] d d# d� d$ d% d
 d
 d& dz d d( d� d) d* d� d+ d, dY d d& dX d/ d d/ d1 d2 d� d4 d5 d d7 d
d� d d4 d� d: d; d� d< d= d� d d> d� d@ dA d{ dC dD d� d dE d� dG dA d� dI dJ dY dL dM d) dO dP d: dR d7 d9 dS dL d� d! dU d� dW d d� dY d5 d� dZ d d� d[ d\ dd] d^ d d< d_ d� dG dF dA da d3 d; d db d> dc dd d da de d� dg dh d	 di d d= d
d dD dl d dx dm dn d� do d d� dq dr d8 ds dt d� dj dv d� dx dy dA dC dv d� d{ d3 d� d| d} d� dV d| ds d7 d� d? d7 d� dl d� d� d� dj d� d� dU d� d dh d? d� d+ dO d d� d d7 dr d d� d� d� d� d� d� d: d d dD ds di d� d' dh dH d� dF d� d* d) d� d� d� d d� d� di dY d" d7 d d@ d� d� d d� d- dV d� d� d� d� dL d� dv d- d� d  d d� d� d d dP dx d� d� d dA d� d d� d� d� dG d0 d d d d d d
d d� d� d  dy d� d d# d@ d$ d% d/ d
 d& d� d d( d� d) d* d� d+ d, dv d d& d� d/ d d� d1 d2 da d4 d5 d d7 d
d� d d4 dp d: d; d� d� d= d: d d> d
d@ dA d dC dD d d dE d� dG dA d� dI dJ d� dL dM d� dO dP d dR d7 d3 dS dL d� d! dU d dW d d� dY d5 dZ dZ d d0 d[ d\ d; d] d^ d% d< d_ d
dG dF d da d3 d d db d� dc dd dy da de d3 dg dh d> di d ds d
d d� dl d d� dm dn d� do d d� dq dr dS ds dt do dj dv d� dx dy d dC dv da d{ d3 dY d| d} d� dV d| d� d7 d� d� d7 d� d� d� d� d� dj d� d� dU d� d9 dh d? d� d+ dO d� d� d d] dr d dY d� d� d� d� d� d' d d d� ds di d� d' dh d� d� dF d d* d) d� d� d� d� d� d� d� d� d" dn d d@ d� d� d d� d- dV dY d� d� d dL d� dA d- d� dl d d� d d d d[ dx d� d� d dA d� d d� d� d� dG d� d d d� d d d d d� d� d  dy d d d# d� d$ d% d? d
 d& d� d d( d� d) d* d� d+ d, d� d d& d� d/ d d� d1 d2 d� d4 d5 d d7 d
d� d d4 d` d: d; d� d< d= d� d d> du d@ dA d� dC dD db d dE d� dG dA dp dI dJ d dL dM d dO dP d� dR d7 d� dS dL d� d! dU d1 dW d dl dY d5 d� dZ d dB d[ d\ d� d] d^ dv d< d_ d� dG dF d� da d3 d� d db dm dc dd d� da de d� dg dh d� di d d8 d d d dl d d� dm dn d# do d dS dq dr d ds dt dZ dj dv d� dx dy d> dC dv d� d{ d3 d� d| d} d� dV d| d� d7 d� d4 d7 d� d� d� d� d� dj d� d dU d� d~ dh d? d� d+ dO d� d� d d dr d d� d� d� d� d� d� d� d d d{ ds di dQ d' dh d� d� dF d% d* d) d� d� d� d d� d� d� d� d" d@ d d@ d d� d d< d- dV d� d� d� dT dL d� d� d- d� d3 d d� d d d d� dx d� d� d dA d� d d� d� d� dG d/ d d db d d d� d d� d[ d  dy d� d d# dj d$ d% dS d
 d& d d d( d� d) d* dO d+ d, d� d d& d� d/ d d d1 d2 d� d4 d5 d d7 d
d� d d4 d� d: d; d� d< d= d& d d> d� d@ dA d� dC dD d& d dE d� dG dA d6 dI dJ d� dL dM d� dO dP d� dR d7 d� dS dL d� d! dU dg dW d d0 dY d5 d+ dZ d d� d[ d\ dd d] d^ dK d< d_ d� dG dF dT da d3 d; d db d> dc dd d da de d� dg dh d	 di d d= d
d dD dl d dx dm dn d� do d d� dq dr d8 ds dt d� dj dv d� dx dy dA dC dv d� d{ d3 d� d| d} d� dV d| ds d7 d� d? d7 d� dl d� d� d� dj d� d� dU d� d dh d? d� d+ dO d d� d d7 dr d d� d� d� d� d� d� d: d d dD ds di d� d' dh dH d� dF d� d* d) d� d� d� d d� d� d� d� d" d\ d d@ d_ d� d d  d- dV dN d� d� d� dL d� d� d- d� dC d d� dd d d� dx d� d� d dA d  d d� dG d� dG d d d d  d d d� d d� d� d  dy d d d# d� d$ d% d" d
 d& d� d d( d� d) d* d' d+ d, dB d d& d{ d/ d df d1 d2 d[ d4 d5 d� d7 d
dM d d4 d d: d; df d< d= d> d d> df d@ dA d� dC dD d� d dE d^ dG dA dd dI dJ d� dL dM d� dO dP dR dR d7 d_ dS dL d� d! dU d� dW d d" dY d5 d� dZ d d
 d[ d\ d d] d^ dp d< d_ d dG dF d da d3 d d db d� dc dd dy da de d3 dg dh d> di d ds d
d d� dl d d� dm dn d� do d d� dq dr dS ds dt do dj dv d� dx dy d dC dv da d{ d3 dY d| d} d� dV d| d� d7 d� d� d7 d� d� d� d� d� dj d� d� dU d� d9 dh d? d� d+ dO d� d� d d] dr d dY d� d� d� d� d� d' d d d� ds di d� d' dh d� d� dF d d* d) d� d� d� d� d� d� d� d� d" d d d@ d� d� d d� d- dV dJ d� d� d  dL d� d` d- d� d� d d� d� d d ds dx d� d� d dA d� d d� d� d� dG d d d df d d d dZ d� d� d  dy d> d d# d� d$ d% d� d
 d& d3 d d( da d) d* d� d+ d, d� d d& dt d/ d d� d1 d2 d% d4 d5 d: d7 d
d� d d4 d� d: d; d� d< d= d� d d> d� d@ dA d� dC dD d d dE d� dG dA dC dI dJ dc dL dM dl dO dP d� dR d7 d[ dS dL d� d! dU d# dW d d� dY d5 d� dZ d d� d[ d\ d d] d^ d� d< d_ d� dG dF d� da d3 d� d db dm dc dd d� da de d� dg dh d� di d d8 d d d dl d d� dm dn d# do d dS dq dr d ds dt dZ dj dv d� dx dy d> dC dv d� d{ d3 d� d| d} d� dV d| d� d7 d� d4 d7 d� d� d� d� d� dj d� d dU d� d~ dh d? d� d+ dO d� d� d d dr d d� d� d� d� d� d� d� d d d{ ds di dQ d' dh d� d� dF d% d* d) d� d� d� d d� d� d� d� d" d@ d d@ d� d� d d d- dV d� d� d� d$ dL d� d� d- d� d� d d� dI d d d� dx d� dW d dA d� d d� ds d� dG d� d d df d d d� d d� dE d  dy d� d d# d� d$ d% dS d
 d& d d d( d� d) d* dO d+ d, d d d& d� d/ d d� d1 d2 d� d4 d5 d� d7 d
d� d d4 d� d: d; d� d< d= d/ d d> d� d@ dA d  dC dD d� d dE dq dG dA d� dI dJ di dL dM d� dO dP dg dR d7 d� dS dL d� d! dU d� dW d d� dY d5 d+ dZ d d� d[ d\ dd d] d^ dK d< d_ d� dG dF dT da d3 d; d db d> dc dd d da de d� dg dh d	 di d d= d
d dD dl d dx dm dn d� do d d� dq dr d8 ds dt d� dj dv d� dx dy dA dC dv d� d{ d3 d� d| d} d� dV d| ds d7 d� d? d7 d� dl d� d� d� dj d� d� dU d� d dh d? d� d+ dO d d� d d7 dr d d� d� d� d� d� d� d: d d dD ds di d� d' dh dH d� dF d� d* d) d� d� d� d d� d� d� d� d" d\ d d@ d_ d� d d  d- dV dN d� d� d� dL d� d� d- d� dC d d� dd d dh dx d� d. d dA d d d� d� d� dG dj d d dg d d dy d d� d� d  dy d� d d# d� d$ d% d+ d
 d& d� d d( d� d) d* dn d+ d, d� d d& d� d/ d d� d1 d2 d� d4 d5 d� d7 d
d� d d4 d� d: d; d� d� d= do d d> d d@ dA d� dC dD d+ d dE dI dG dA d dI dJ dL dL dM dy dO dP d dR d7 d� dS dL d4 d! dU di dW d d" dY d5 d� dZ d d
 d[ d\ d d] d^ dp d< d_ d dG dF d da d3 d d db d� dc dd dy da de d3 dg dh d> di d ds d
d d� dl d d� dm dn d� do d d� dq dr dS ds dt do dj dv d� dx dy d dC dv da d{ d3 dY d| d} d� dV d| d� d7 d� d� d7 d� d� d� d� d� dj d� d� dU d� d9 dh d? d� d+ dO d� d� d d] dr d dY d� d� d� d� d� d' d d d� ds di d� d' dh d� d� dF d d* d) d� d� d� d� d� d� d� d� d" d d d@ d� d� d d� d- dV d0 d� d� d� dL d� d� d- d� d� d d� d� d d d} dx d� d� d dA d� d d� d� d� dG dA d d dq d d d� d d� d� d  dy d[ d d# d� d$ d% d= d
 d& d d d( d d) d* d� d+ d, d d d& dD d/ d dM d1 d2 df d4 d5 d� d7 d
d� d d4 d� d: d; d0 d< d= d� d d> d� d@ dA d� dC dD d� d dE d dG dA dC dI dJ dc dL dM d' dO dP d: dR d7 d[ dS dL d� d! dU d# dW d d� dY d5 d� dZ d d� d[ d\ d d] d^ d� d< d_ d� dG dF d� da d3 d� d db dm dc dd d� da de d� dg dh d� di d d8 d d d dl d d� dm dn d# do d dS dq dr d ds dt dZ dj dv d� dx dy d> dC dv d� d{ d3 d� d| d} d� dV d| d� d7 d� d4 d7 d� d� d� d� d� dj d� d dU d� d~ dh d? d� d+ dO d� d� d d dr d d� d� d� d� d� d� d� d d d{ ds di dQ d' dh d� d� dF d% d* d) d� d� d� d d� d� d� d� d" d@ d d@ d� d� d d d- dV d� d� d� d$ dL d� d� d- d� d� d d� dI d d d� dx d� d	 d dA d� d d� d� d� dG dm d d df d d d� d d� dE d  dy d� d d# d� d$ d% d; d
 d& d� d d( d� d) d* d, d+ d, d d d& d� d/ d d� d1 d2 d� d4 d5 d! d7 d
d� d d4 dw d: d; d� d< d= d� d d> d� d@ dA d{ dC dD d� d dE d� dG dA d� dI dJ d� dL dM d� dO dP d� dR d7 d� dS dL d� d! dU d� dW d d� dY d5 d+ dZ d d� d[ d\ dd d] d^ dK d< d_ d� dG dF dT da d3 d; d db d> dc dd d da de d� dg dh d	 di d d= d
d dD dl d dx dm dn d� do d d� dq dr d8 ds dt d� dj dv d� dx dy dA dC dv d� d{ d3 d� d| d} d� dV d| ds d7 d� d? d7 d� dl d� d� d� dj d� d� dU d� d dh d? d� d+ dO d d� d d7 dr d d� d� d� d� d� d� d: d d dD ds di d� d' dh dH d� dF d� d* d) d� d� d� d d� d� d� d� d" d\ d d@ d_ d� d dK d- dV d� d� d� dw dL d� dS d- d� d� d d� d� d d d% dx d� df d dA dD d d� dv d� dG dd d d6 d d d� d d� d! d  dy dH d d# d d$ d% d# d
 d& d( d d( dC d) d* dL d+ d, d6 d d& d d/ d d d1 d2 d, d4 d5 d� d7 d
dM d d4 d� d: d; d d< d= d> d d> d' d@ dA d� dC dD d� d dE d� dG dA d dI dJ d~ dL dM dw dO dP d� dR d7 d� dS dL d� d! dU di dW d d" dY d5 d� dZ d d
 d[ d\ d d] d^ dp d< d_ d dG dF d da d3 d d db d� dc dd dy da de d3 dg dh d> di d ds d
d d� dl d d� dm dn d� do d d� dq dr dS ds dt do dj dv d� dx dy d dC dv da d{ d3 dY d| d} d� dV d| d� d7 d� d� d7 d� d� d� d� d� dj d� d� dU d� d9 dh d? d� d+ dO d� d� d d] dr d dY d� d� d� d� d� d' d d d� ds di d� d' dh d� d� dF d d* d) d� d� d� d� d� d� d� d� d" d d d@ d� d� d d� d- dV dC d� d� d� dL d� d� d- d� d d d� d� d d df dx d� d� d dA dj d d� d� d� dG d" d d d� d d d0 d d� d� d  dy d� d d# dW d$ d% d5 d
 d& d� d d( d d) d* d� d+ d, dD d d& dD d/ d d� d1 d2 d% d4 d5 d: d7 d
d� d d4 d� d: d; d� d< d= d� d d> d� d@ dA d� dC dD d� d dE dS dG dA dO dI dJ d0 dL dM d� dO dP d� dR d7 dl dS dL dm d! dU d# dW d d� dY d5 d� dZ d d� d[ d\ d d] d^ d� d< d_ d� dG dF d� da d3 d� d db dm dc dd d� da de d� dg dh d� di d d8 d d d dl d d� dm dn d# do d dS dq dr d ds dt dZ dj dv d� dx dy d> dC dv d� d{ d3 d� d| d} d  dV d| d
 d7 d� d~ d7 d� d� d� d� d dj d� d� dU d� d dh d? d� d+ dO d� d� d d� dr d d� d� d� d� d� d� d" d d d� ds di d� d� dh d� d� dF dc d* d) d d� d� d� d� d� d� d� d" d� d d@ d� d� d d# d- dV d� d� d� d� dL d� d  d- d� d d d� d� d d d/ dx d� d� d dA d� d d� d d� dG d� d d d� d d d� d d� d d  dy d4 d d# d� d$ d% d� d
 d& d� d d( d d) d* d� d+ d, do d d& d� d/ d d� d1 d2 d� d4 d5 d d7 d
d� d d4 d� d: d; dk d< d= d
d d> d d@ dA d	 dC dD d� d dE d� dG dA d= dI dJ d] d� dM d) dO dP d> dR d7 dl dS dL dR d! dU d� dW d d, dY d5 d� dZ d dA d[ d\ dd d] d^ d� d< d_ d= dG dF d da d3 d; d db d� dc dd d] da de db dg dh d� di d d/ d
d d8 dl d d� dm dn d� do d d� dq dr di ds dt d� dj dv d� dx dy d� dC dv d� d{ d3 dj d| d} d� dV d| d� d7 d� d
 d7 d� d� d� d� dG d� d� dr dU d� d dh d? d
 d+ dO d� d� d d� dr d d� d� d� d� d� d� dx d d dj ds di d� d' dh d� d� dF d d* d) d� d� d� d6 d� d� d� d� d" d� d d@ d d� d d� d- dV d� d� d� dI dL d� d? d- d� dZ d d� d d d d� dx d� d7 d dA d� d d� d� d� dG d� d d d d d d� d d� d� d  dy d d d# dB d$ d% d� d
 d& d' d d( d, d) d* d� d+ d, d- d d& dh d/ d d0 d1 d2 d3 d4 d5 dq d7 d
d� d d4 d9 d: d; d� d< d= d� d d> d? d@ dA d� dC dD d d dE dO dG dA d5 dI dJ d� dL dM d0 dO dP dQ dR d7 d� dS dL d� d! dU d  dW d dC dY d5 d* dZ d dB d[ d\ d> d] d^ d/ d< d_ dx dG dF d da d3 d d db d dc dd d da de d� dg dh dL di d d2 d
d d" dl d dI dm dn d do d d	 dq dr d+ ds dt d� dj dv d� dx dy du dC dv d' d{ d3 d� d| d} d~ dV d| d� d7 d� d� d7 d� d� d� d� dy dj d� d� dU d� dk dh d? d� d+ dO d� d� d d� dr d dO d� d� d@ d� d� dJ d d d� ds di d$ d' dh d� d� dF de d* d) d� d� d� d� d� d� d� d� d" d� d d@ d. d� d d� d- dV dq d� d� d� dL d� d d- d� d d d� du d d d dx d� d� d dA d5 d d� d' d� dG d0 d d dj d d d� d d� d� d  dy d d d# d� d$ d% dA d
 d& d� d d( d6 d) d* d� d+ d, d8 d d& d0 d/ d d� d1 d2 d� d4 d5 d6 d7 d
d` d d4 d� d: d; d� d< d= d d d> d� d@ dA d7 dC dD d� d dE d dG dA d� dI dJ dN dL dM do dO dP d_ dR d7 d� dS dL d d! dU dj dW d d� dY d5 d dZ d d d[ d\ d d] d^ d� d< d_ d2 dG dF d� da d3 d� d db d� dc dd d� da de d� dg dh dU di d d� d
d d! dl d d� dm dn de do d d� dq dr d� ds dt d� dj dv d` dx dy d dC dv d d{ d3 d` d| d} d dV d| d� d7 d� d� d7 d� d d� d� d� dj d� dB dU d� d� dh d? ds d+ dO d6 d� d d� dr d d~ d� d� d� d� d� d� d d d5 ds di d� d' dh dr d� dF d� d* d) d� d d� d^ d� d� d' d� d" d d d@ d� d� d ds d- dV d{ d� d� d� dL d� d� d- d� d d d� dG d d d� dx d� d� d dA dD d d� d� d� dG d# d d d� d d d� d d� d d  dy d< d d# d+ d$ d% d� d
 d& d� d d( d d) d* d
d+ d, d� d d& d� d/ d d� d1 d2 d� d4 d5 d� d7 d
d4 d d4 d� d: d; d& d< d= dL d d> d� d@ dA d� dC dD d� d dE da dG dA dA dI dJ d dL dM d� dO dP d� dR d7 d� dS dL d d! dU d dW d d� dY d5 d� dZ d d� d[ d\ d� d] d^ d' d< d_ dS dG dF d� da d3 d� d db d� dc dd d� da de d3 dg dh d� di d d� d
d d� dl d d� dm dn d� do d d� dq dr di ds dt dt dj dv dV dx dy dK dC dv d� d{ d3 d d| d} d� dV d| dd d7 d� d} d7 d� d� d� d� dB dj d� d dU d� dv dh d? dz d+ dO d� d� d d� dr d d� d� d� d� d� d� d[ d d d8 ds di d� d' dh dh d� dF d� d* d) d� d� d� d6 d� d� dS d� d" d d d@ d� d� d dW d- dV df d� d� dh dL d� d� d- d� d� d d� d� d d d� dx d� d7 d dA d� d d� d] d� dG d� d d d� d d d d d� d� d  dy d d d# dB d$ d% d� d
 d& d' d d( d6 d) d* d� d+ d, d- d d& d( d/ d d� d1 d2 d3 d4 d5 d� d7 d
dr d d4 d9 d: d; d} d< d= d	 d d> d? d@ dA d5 dC dD dh d dE dO dG dA d� dI dJ d9 dL dM dN dO dP d> dR d7 d� dS dL dq d! dU d dW d d: dY d5 d* dZ d dA d[ d\ d� d] d^ d  d< d_ d` dG dF dda d3 d d db d dc dd d da de ds dg dh d di d d2 d
d d� dl d dc dm dn d[ do d d dq dr d! ds dt d- dj dv dJ dx dy d� dC dv d� d{ d3 d d| d} d& dV d| d� d7 d� d? d7 d� d
 d� d� d dj d� d� dU d� d� dh d? dw d+ dO d� d� d do dr d d� d� d� d� d� d� d= d d dR ds di d� d' dh d^ d� dF d� d* d) d� d� d� d� d� d� d� d� d" dP d d@ dl d� d d d- dV dH d� d� du dL d� dS d- d� dh d d� du d d d� dx d� d� d dA dm d d� d� d� dG d� d d dy d d dT d d� d} d  dy d? d d# d� d$ d% d d
 d& d4 d d( d� d) d* d� d+ d, d� d d& d� d/ d dH d1 d2 di d4 d5 d� d7 d
d� d d4 d� d: d; d� d< d= d� d d> d d@ dA d� dC dD d� d dE dH dG dA d> dI dJ d� dL dM d� dO dP d4 dR d7 d� dS dL d d! dU d� dW d d~ dY d5 d� dZ d d� d[ d\ d� d] d^ d� d< d_ d� dG dF d da d3 d� d db dd dc dd d� da de d# dg dh d= di d d� d
d d! dl d d" dm dn d� do d dR dq dr d� ds dt d� dj dv dS dx dy d� dC dv dV d{ d3 d� d| d} d� dV d| d� d7 d� d� d7 d� d d� d� d� dj d� dB dU d� d dh d? dd d+ dO d� d� d d� dr d d~ d� d� d� d� d� d d d d ds di dz d' dh dK d� dF d� d* d) dk d� d� d� d� d� dm d� d" d d d@ d� d� d d� d- dV d� d� d� d2 dL d� d� d- d� dL d d� d d d df dx d� dW d dA d_ d d� dE d� dG d� d d d� d d d� d d� d� d  dy d( d d# d+ d$ d% d� d
 d& d� d d( d~ d) d* d d+ d, d� d d& d� d/ d d� d1 d2 dh d4 d5 d� d7 d
d d d4 d~ d: d; d^ d< d= d: d d> d� d@ dA dV dC dD dr d dE d� dG dA dj dI dJ d9 dL dM d� dO dP d� dR d7 d
dS dL d� d! dU d� dW d d0 dY d5 d# dZ d d� d[ d\ dr d] d^ dS d< d_ d. dG dF d� da d3 d d db dX dc dd d da de d� dg dh d� di d dP d
d d� dl d d dm dn d\ do d d dq dr dm ds dt d� dj dv d� dx dy dK dC dv d� d{ d3 d( d| d} d dV d| d; d7 d� dG d7 d� d[ d� d� d� dj d� d� dU d� d� dh d? dE d+ dO d� d� d d dr d d+ d� d� d d� d� dz d d d ds di dm d' dh d� d� dF d d* d) d� d� d� d� d� d� d� d� d" d� d d@ dc d� d d� d- dV d7 d� d� dw dL d� dE d- d� d� d d� d� d d d3 dx d� d. d dA dI d d� d� d� dG d� d d d� d d d d d� d� d  dy da d d# dB d$ d% d/ d
 d& d d d( d_ d) d* dL d+ d, d� d d& d! d/ d d0 d1 d2 d3 d4 d5 dP d7 d
d@ d d4 d' d: d; d2 d< d= d� d d> d? d@ dA d! dC dD d� d� dE d� dG dA d dI dJ dE dL dM d� dO dP dQ dR d7 d� dS dL dq d! dU da dW d d� dY d5 dP dZ d d� d[ d\ dm d] d^ d� d< d_ d% dG dF d- da d3 d d db d dc dd d� da de d� dg dh dJ di d d2 d
d d dl d d� dm dn d� do d d� dq dr d� ds dt d5 dj dv d� dx dy d dC dv d� d{ d3 d� d| d} d] dV d| d� d7 d� d� d7 d� d� d� d� d� dj d� d� dU d� d� dh d? d$ d+ dO d� d� d d� dr d d9 d� d� d? d� d� dN d d d� ds di dJ d' dh d� d� dF dr d* d) d� d� d� d� d� d� d� d� d" d� d d@ d� d� d dQ d- dV dm d� d� d� dL d� d� d- d� dM d d� dB d d d dx d� d� d dA dm d d� d d� dG d� d d d� d d d� d d� d� d  dy d$ d d# d� d$ d% d� d
 d& df d d( d6 d) d* d� d+ d, d} d d& dd d/ d d� d1 d2 d� d4 d5 d d7 d
d� d d4 d d: d; d] d< d= d� d d> d� d@ dA d� dC dD dQ d dE d� dG dA d dI dJ d� dL dM dL dO dP d� dR d7 d� dS dL d d! dU df dW d d� dY d5 do dZ d d d[ d\ d d] d^ d� d< d_ d: dG dF d� da d3 d� d db d� dc dd d� da de d� dg dh dm di d dS d
d dx dl d d� dm dn de do d d# dq dr d� ds dt dj dj dv d dx dy d2 dC dv d= d{ d3 d� d| d} d dV d| d� d7 d� d� d7 d� d d� d� d� dj d� d� dU d� d� dh d? d� d+ dO d� d� d d� dr d dP d� d� d� d� d� d� d d d� ds di d� d' dh dQ d� dF d� d* d) d d� d� dV d� d� d� d� d" d d d@ d d� d dK d- dV di d� d� d� dL d� d� d- d� dm d d� dG d d d� dx d� d� d dA d@ d d� dC d� dG d� d d d� d d dC d d� d� d  dy d& d d# dV d$ d% d� d
 d& d� d d( d d) d* d� d+ d, d� d d& d d/ d d� d1 d2 di d4 d5 d� d7 d
d d d4 d� d: d; d� d< d= d� d d> d� d@ dA d� dC dD d� d dE dr dG dA dQ dI dJ d� dL dM d� dO dP d� dR d7 d� dS dL d d! dU d dW d d� dY d5 d� dZ d dW d[ d\ d� d] d^ d d< d_ d� dG dF d� da d3 d� d db d8 dc dd dt da de d{ dg dh d� di d d� d
d dg dl d dC dm dn d� do d d1 dq dr d� ds dt d< dj dv dV dx dy d� dC dv d� d{ d3 d� d| d} d� dV d| d> d7 d� d� d7 d� d d� d� dI dj d� d~ dU d� d� dh d? d� d+ dO d� d� d d� dr d d^ d� d� d� d� d� d{ d d d� ds di d� d' dh dY d� dF d� d* d) d� d� d� d6 d� d� dS d� d" d� d d@ d d� d dW d- dV d� d� d� d� dL d� d3 d- d� d� d d� d d d dm dx d� d7 d dA d� d d� d] d� dG dL d d d d d dF d d� dV d  dy d d d# d� d$ d% d� d
 d& d' d d( d� d) d* d� d+ d, d� d d& d. d/ d d0 d1 d2 dk d4 d5 dd d7 d
d� d d4 d9 d: d; d2 d< d= d� d d> d@ d@ dA d� dC dD dF d dE dO dG dA d� dI dJ d� dL dM d( dO dP d dR d7 d� dS dL d� d! dU d� dW d d dY d5 d� dZ d d� d[ d\ d� d] d^ d� d< d_ d
dG dF d_ da d3 d� d db d� dc dd d� da de d~ dg dh d` di d d@ d
d d� dl d d
dm dn d� do d dm dq dr dT ds dt d� dj dv d� d� dy d� dC dv d� d{ d3 d� d| d} dm dV d| d� d7 d� d d7 d� d� d� d� d� dj d� d� dU d� d� dh d? d� d+ dO d d� d d� dr d d d� d� dw d� d� d� d d dG ds di dk d' dh d� d� dF d d* d) d� d� d� d+ d� d� d� d� d" d� d d@ d d� d d� d- dV dC d� d� d� dL d� dv d- d� d� d d� d d d d dx d� d� d dA d� d d� d� d� dG d� d d d� d d d� d d� d9 d  dy d d d# d� d$ d% d� d
 d& d� d d( d� d) d* d� d+ d, d� d d& d� d/ d d� d1 d2 d d4 d5 d d7 d
d� d d4 d` d: d; d� d< d= d� d d> d� d@ dA d� dC dD d* d dE d] dG dA d� dI dJ dP dL dM d� dO dP d� dR d7 dX dS dL d� d! dU d6 dW d d� dY d5 d0 dZ d d� d[ d\ d� d] d^ d! d< d_ d� dG dF d� da d3 d� d db d� dc dd d^ da de d� dg dh ds di d dH d
d dv dl d d� dm dn d3 do d dv dq dr d ds dt dW dj dv d- dx dy d* dC dv d d{ d3 d d| d} d6 dV d| dS d7 d� d� d7 d� d� d� d� d� dj d� d= dU d� d[ dh d? d� d+ dO d� d� d dy dr d d� d� d� d d� d� d� d d d3 ds di d� d' dh d� d� dF d� d* d) dd� d� d& d� d� d d� d" d d d@ d d� d d� d- dV d� d� d� d� dL d� d� d- d� d� d d� dV d d d� dx d� d d dA d) d d� dh d� dG d� d d d d d d� d d� d d  dy d d d# d� d$ d% dt d
 d& dD d d( d_ d) d* d� d+ d, d� d d& dU d/ d d� d1 d2 d d4 d5 d d7 d
d d d4 d� d: d; d� d< d= d� d d> d� d@ dA d{ dC dD d& d dE d� dG dA d� dI dJ d� dL dM d� dO dP d� dR d7 d� dS dL d d! dU d� dW d d dY d5 d� dZ d dW d[ d\ dn d] d^ d� d< d_ d� dG dF d� da d3 d� d db d dc dd d� da de d dg dh d di d d� d
d d� dl d d� dm dn d� do d d� dq dr d� ds dt d� dj dv d� dx dy dU dC dv d� d{ d3 d� d| d} d8 dV d| d. d7 d� d d7 d� d� d� d� dZ dj d� d� dU d� dk dh d? d| d+ dO dp d� d d~ dr d d� d� d� d� d� d� dL d d dj ds di d d' dh d d� dF dP d* d) d� d� d� d d� d� d` d� d" d� d d@ d� d� d d� d- dV d� d� d� d7 dL d� d� d- d� d  d d� d� d d d dx d� d� d dA d> d d� dv d� dG dd d d d d d� d d� d& d  dy d8 d d# da d$ d% d� d
 d& d! d d( d� d) d* d3 d+ d, dD d d& d� d/ d d| d1 d2 d� d4 d5 d� d7 d
d� d d4 d d: d; d d< d= d� d d> d? d@ dA dB dC dD d) d dE dv dG dA d� dI dJ d� dL dM dN dO dP dQ dR d7 d� dS dL dq d! dU dV dW d d dY d5 d* dZ d dk d[ d\ d> d] d^ d d< d_ d` dG dF d da d3 d d db d� dc dd d da de d� dg dh dJ di d d� d
d d dl d d dm dn d� do d d� dq dr d� ds dt d% d� dv d� dx dy du dC dv d' d{ d3 d� d| d} d~ dV d| d� d7 d� d d7 d� d% d� d� d� dj d� d� dU d� d� dh d? d$ d+ dO d� d� d d� dr d d� d� d� dX d� d� dN d d d� ds di dJ d' dh dH d� dF dp d* d) d d� d� d� d� d� d� d� d" dP d d@ d� d� d d+ d- dV dO d� d� du dL d� da d- d� d} d d� du d d d dx d� d� d dA dE d d� d� d� dG d� d d dy d d d� d d� d� d  dy d d d# d� d$ d% d d
 d& dE d d( d< d) d* d� d+ d, d d d& d� d� d d� d1 d2 d� d4 d5 d6 d7 d
d� d d4 d d: d; d� d< d= d� d d> d� d@ dA d� dC dD d d dE d� dG dA d dI dJ d� dL dM d� dO dP d� dR d7 dP dS dL d� d! dU d dW d d dY d5 d6 dZ d d  d[ d\ d= d] d^ dA d< d_ dL dG dF d/ da d3 d d db d dc dd d^ da de d� dg dh ds di d dH d
d dv dl d d� dm dn d3 do d dv dq dr d ds dt dW dj dv d- dx dy d� dC dv d� d{ d3 d� d| d} d dV d| dI d7 d� d% d7 d� da d� d� dQ dj d� d� dU d� d� dh d? d d+ dO d d� d d� dr d d� d� d� d� d� d� d" d d d� ds di d� d� dh d� d� dF dc d* d) d� d� d� d& d� d� d d� d" d d d@ d d� d d� d- dV d� d� d� d� dL d� d� d- d� d� d d� d� d d d� dx d� d� d dA d� d d� d� d� dG d� d d d� d d d� d d� d d  dy d4 d d# d� d$ d% d� d
 d& d� d d( d d) d* d� d+ d, do d d& d� d/ d d& d1 d2 d� d4 d5 d� d7 d
d d d4 dr d: d; dC d< d= d� d d> dC d@ dA d� dC dD d� d dE d$ dG dA d� dI dJ d= dL dM d dO dP d� dR d7 db dS dL dk d! dU d� dW d d0 dY d5 d9 dZ d dW d[ d\ d� d] d^ dC d< d_ d� dG dF dA da d3 d) d db d� dc dd d� da de d dg dh d� di d d9 d
d d7 dl d d8 dm dn d� do d d� dq dr d ds dt d dj dv d� dx dy d1 dC dv d� d{ d3 d� d| d} d� dV d| d� d7 d� d& d7 d� dG d� d� d} dj d� d� dU d� d� dh d? d� d+ dO d� d� d d~ dr d d� d� d� d� d� d� dg d d dR ds di d� d' dh d� d� dF d� d* d) d� d� d� d� d� d� d� d� d" d� d d@ dt d� d d� d- dV d7 d� d� d� dL d� d� d- d� d  d d� d� d d d dx d� d� d dA d> d d� dv d� dG dd d d d d d� d d� d� d  dy d� d d# d` d$ d% d� d
 d& d� d d( d� d) d* d� d+ d, d d d& dF d/ d d� d1 d2 d* d4 d5 d� d7 d
d� d d4 d� d: d; d� d< d= da d d> d� d@ dA de dC dD d� d dE d dG dA d� dI dJ d, dL dM d� dO dP d� dR d7 dG dS dL d0 d% dU d� dW d d� dY d5 d� dZ d dt d[ d\ dk d] d^ d d< d_ dd dG dF dH da d3 d� d db d� dc dd d� da de d� dg dh d" di d d- d
d d+ dl d d� dm dn d� do d d� dq dr d� ds dt dY dj dv d� dx dy d� dC dv da d{ d3 dY d| d} d� dV d| d� d7 d� d� d7 d� d9 d� d� d� dj d� d` dU d� d� dh d? d� d+ dO d� d� d d� dr d d. d� d� d� d� d� d� d d d� ds di d� d' dh d� d� dF d d* d) dL d� d� d� d� d� da d� d" d d d@ d( d� d d d- dV dj d� d� dM dL d� d� d- d� d� d d� d� d d d� dx d� d� d dA d� d d� d� d� dG d� d d d� d d d� d d� d9 d  dy d� d d# d7 d$ d% d� d
 d& dE d d( d� d) d* d� d+ d, d� d d& dt d/ d d� d1 d2 d
 d4 d5 dY d7 d
d� d d4 d� d: d; d� d< d= d� d d> d� d@ dA d� dC dD dL d dE d� dG dA dR dI dJ d� dL dM d} dO dP dh dR d7 d� dS dL d� d! dU d� dW d d� dY d5 d� dZ d d% d[ d\ dg d] d^ dK d< d_ d) dG dF d da d3 d d db d� dc dd dA da de d dg dh dm di d d� d
d d= dl d d� dm dn d� do d d� dq dr dB ds dt d: dj dv d dx dy d� dC dv d d{ d3 d` d| d} d� dV d| dp d7 d� d� d7 d� d� d� d� d	 dj d� d( dU d� d[ dh d? d5 d+ dO d  d� d d dr d d� d� d� d~ d� d� d� d d d ds di d� d' dh d� d� dF d� d* d) d� d� d� d� d� d� d$ d� d" d6 d d@ d) d� d d� d- dV d� d� d� d� dL d� d� d- d� d d d� d� d d d� dx d� d d dA d_ d d� dw d� dG dj d d dq d d d� d d� d� d  dy d� d d# dj d$ d% dY d
 d& d� d d( d d) d* do d+ d, d� d d& d� d/ d d� d1 d2 d� d4 d5 d d7 d
d d d4 d� d: d; d^ d< d= d: d d> d� d@ dA d� dC dD d d dE d dG dA dA dI dJ d dL dM d� dO dP d dR d7 d_ dS dL d d! dU d dW d d� dY d5 d dZ d d� d[ d\ d� d] d^ d� d< d_ d� dG dF d� da d3 d� d db d� dc dd d da de d� dg dh d� di d d/ d
d d8 dl d d, dm dn d� do d di dq dr d� ds dt d� dj dv d� dx dy dK dC dv d� d{ d3 d( d| d} d� dV d| d� d7 d� d
 d7 d� d� d� d� dG d� d� d� dU d� d� dh d? d
 d+ dO d� d� d d� dr d d d� d� d� d� d� dx d d d8 ds di d� d' dh dh d� dF d� d* d) d� d� d� d6 d� d� d� d� d" d� d d@ d d� d dW d- dV d d� d� d� dL d� d3 d- d� d� d d� d d d d' dx d� d! d dA d� d d� d\ d� dG d� d d d� d d dF d d� dV d  dy d� d d# d� d$ d% d� d
 d& d' d d( d( d) d* d d+ d, d� d d& d� d/ d d� d1 d2 d d4 d5 dP d7 d
d8 d d4 d� d: d; d� d< d= d� d d> d% d@ dA d: dC dD d d dE d( dG dA d^ dI dJ d� dL dM dM dO dP d� dR d7 d� dS dL d4 d! dU d� dW d d� dY d5 d/ dZ d d d[ d\ d` d] d^ d� d< d_ d� dG dF d� da d3 df d db d1 dc dd d� da de d� dg dh d� di d d� d
d d dl d d� dm dn d� do d d� dq dr d� ds dt dY dj dv d� dx dy d� dC dv d� d{ d3 d� d| d} d dV d| dd d7 d� d� d7 d� dP d� d� d� dj d� d� dU d� d� dh d? d� d+ dO d� d� d d dr d d d� d� dY d� d� d, d d dr ds di d d' dh d� d� dF d� d* d) d� d� d� dY d� d� d@ d� d" dn d d@ d� d� d d� d- dV dJ d� d� dI dL d� d� d- d� d� d d� d� d d dw dx d� d� d dA d� d d� da d� dG d� d d d� d d d d d� d� d  dy d� d d# d� d$ d% d� d
 d& dr d d( d� d) d* d5 d+ d, d� d d& d� d/ d d� d1 d2 d7 d4 d5 dY d7 d
d� d d4 d` d: d; d> d< d= d7 d d> d� d@ dA dx dC dD d� d dE d� dG dA d dI dJ d� dL dM d� dO dP d. dR d7 d� dS dL d� d! dU d� dW d d dY d5 dn dZ d d d[ d\ d� d] d^ d� d< d_ d1 dG dF d da d3 dR d db de dc dd dU da de d dg dh d� di d dg d
d d� dl d d dm dn d\ do d d_ dq dr d
 ds dt d dj dv d� dx dy dV dC dv d< d{ d3 d� d| d} d� dV d| dp d7 d� d� d7 d� d� d� d� d	 dj d� d� dU d� d[ dh d? d� d+ dO dh d� d d� dr d d� d� d� d� d� d� d� d d d� ds di d� d' dh d d� dF d	 d* d) d d� d� d� d� d� d� d� d" d d d@ d d� d d\ d- dV d� d� d� dG dL d� d d- d� d� d d� d� d d do dx d� d# d dA d� d d� d3 d� dG d� d d d d d d� d d� d� d  dy d+ d d# di d$ d% d� d
 d& d d d( d� d) d* d� d+ d, d� d d& d� d/ d d� d1 d2 d
 d4 d5 dY d7 d
d d d4 dU d: d; d� d< d= d� d d> d� d@ dA d{ dC dD d� d dE d� dG dA dV dI dJ d� dL dM d� dO dP d� dR d7 d� dS dL dm d! dU d� dW d d| dY d5 d? dZ d d d[ d\ d� d] d^ dd< d_ d6 dG dF d� da d3 d� d db d� dc dd dj da de d dg dh dn di d d� d
d dG dl d dM dm dn d	 do d d� dq dr d ds dt d� dj dv d� dx dy d; dC dv do d{ d3 dC d| d} d� dV d| d� d7 d� d& d7 d� dG d� d� d dj d� dA dU d� d* dh d? d) d+ dO dv d� d d� dr d d� d� d� d� d� d� d� d d d ds di d� d' dh d d� dF db d* d) d" d� d� d� d� d� di dY d" d� d d@ dl d� d d� d- dV d� d� d� da dL d� d� d- d� d� d d� d� d d d dx d� dU d dA d d d� d� d� dG dd d d< d d dj d d� d� d  dy d� d d# d� d$ d% d� d
 d& d� d d( d� d) d* d� d+ d, d� d d& d� d/ d di d1 d2 d� d4 d5 d� d7 d
d� d d4 d� d: d; d� d< d= dz d d> d4 d@ dA d� dC dD d� d dE d� dG dA d� dI dJ d� dL dM d� dO dP d� dR d7 dG dS dL d� d! dU d� dW d d� dY d5 d� dZ d dd d[ d\ d� d] d^ dQ d� d_ dd dG dF d� da d3 d� d db d� dc dd dH da de d� dg dh d� di d d d
d d dl d d� dm dn d� do d d� dq dr d� ds dt db dj dv d4 dx dy d� dC dv d� d{ d3 dc d| d} d� dV d| d d7 d� d� d7 d� d� d� d� dD dj d� d� dU d� d� dh d? d d+ dO d d� d d dr d dY d� d� dY d� d� d� d d dG ds di dk d' dh d	 d� dF d d* d) d� d� d� d� d� d� d� d� d" dP d d@ d� d� d d+ d- dV dO d� d� du dL d� da d- d� dN d d� du d d d dx d� d� d dA dm d d� d- d� dG d� d d dy d d d� d d� d� d  dy dM d d# d� d$ d% d d
 d& d d d( d= d) d* d- d+ d, d d d& d" d/ d d� d1 d2 d- d4 d5 d d7 d
d� d d4 d6 d: d; d` d< d= d= d d> d� d@ dA d� dC dD d� d dE d2 dG dA di dI dJ d� dL dM dp dO dP d dR d7 d� dS dL d d! dU d� dW d d dY d5 d� dZ d d d[ d\ d d] d^ d� d< d_ d� dG dF d� da d3 d� d db d� dc dd d� da de d� dg dh d� di d d7 d
d d! dl d d� dm dn de do d d dq dr d� ds dt d� dj dv d` dx dy dp dC dv dV d{ d3 d� d| d} d� dV d| d4 d7 d� d� d7 d� d d� d� d� dj d� dB dU d� d� dh d? dZ d+ dO d6 d� d d� dr d d� d� d� dA d� d� d� d d d� ds di d� d' dh d� d� dF d� d* d) d d� d� dV d� d� d� d� d" d� d d@ d d� d d3 d- dV d� d� d� d dL d� d d- d� d� d d� dr d d dj dx d� d� d dA d� d d� d� d� dG dx d d d� d d d0 d d� d� d  dy dz d d# dk d$ d% d� d
 d& d� d d( d d) d* d� d+ d, do d d& d� d/ d d� d1 d2 d� d4 d5 d d7 d
d� d d4 d� d: d; dk d< d= d
d d> d d@ dA d	 dC dD d� d dE d� dG dA d= dI dJ d� dL dM d� dO dP d: dR d7 d� dS dL dk d! dU do dW d d: dY d5 d  dZ d d; d[ d\ d� d] d^ dm d< d_ de dG dF dA da d3 d| d db db dc dd d` da de d dg dh d� di d d d
d d� dl d d� dm dn d� do d d� dq dr d� ds dt dG dj dv d� dx dy dV dC dv d d{ d3 d� d| d} d dV d| da d7 d� d? d7 d� d d� d� dY dj d� d� dU d� d dh d? d. d+ dO d� d� d dM dr d d� d� d� d� d� d� d d d d5 ds di d� d' dh d� d� dF d� d* d) d� d� d� d� d� d� d� d� d" d� d d@ d� d� d d� d- dV d� d� d� d� dL d� d� d- d� d~ d d� d� d d d� dx d� d d dA d> d d� dv d� dG dd d d� d d dY d d� d d  dy d� d d# d! d$ d% d� d
 d& d d d( dT d) d* d� d+ d, d d d& d� d/ d d� d1 d2 d� d4 d5 d� d7 d
d= d d4 d d: d; d� d� d= d9 d d> d� d@ dA dO dC dD dc d dE d� dG dA d^ dI dJ d] d� dM d dO dP d^ dR d7 d3 dS dL d2 d! dU d( dW d dM dY d5 d� dZ d d	 d[ d\ d� d] d^ d8 d< d_ ddG dF d� da d3 d d db d� dc dd du da de d� dg dh d� di d ds d
d d� dl d d� dm dn d do d d� dq dr d: ds dt dY dj dv d\ dx dy d� dC dv dn d{ d3 d� d| d} d dV d| d� d7 d� d� d7 d� d� d� d� d� dj d� d� dU d� db dh d? d	 d+ dO d d� d d dr d d d� d� d� d� d� d� d d d� ds di d� d' dh d� d� dF d d* d) d� d� d� d� d� d� d� d� d" dP d d@ d� d� d d+ d- dV dO d� d� du dL d� da d- d� dN d d� du d d d dx d� d� d dA dm d d� d- d� dG d� d d dy d d d� d d� d� d  dy dM d d# d� d$ d% d d
 d& d d d( d= d) d* d- d+ d, d d d& d" d/ d d� d1 d2 d- d4 d5 d d7 d
d� d d4 d6 d: d; d` d< d= dY d d> d� d@ dA d� dC dD d� d dE d4 dG dA d� dI dJ db dL dM dL dO dP dd dR d7 d� dS dL d* d! dU d� dW d dD dY d5 d� dZ d d] d[ d\ d d] d^ d� d< d_ d� dG dF d da d3 d$ d db d� dc dd d� da de d� dg dh d� di d d7 d
d d� dl d d dm dn d� do d d# dq dr d� ds dt d� dj dv d� dx dy d! dC dv d d{ d3 d� d| d} d� dV d| dp d7 d� d d7 d� d� d� d� d� dj d� d= dU d� d� dh d? d d+ dO dx d� d d dr d d� d� d� dA d� d� d� d d d3 ds di dK d' dh dQ d� dF d� d* d) d
d� d� dV d� d� d� d� d" d� d d@ d{ d� d d� d- dV d d� d� d� dL d� d d- d� d� d d� d� d d dr dx d� d d dA d- d d� d� d� dG d= d d d� d d d� d d� d< d  dy d& d d# d� d$ d% d� d
 d& d� d d( d d) d* di d+ d, d� d d& d� d/ d d d1 d2 d d4 d5 d� d7 d
d� d d4 d� d: d; d^ d< d= d: d d> d� d@ dA d� dC dD d� d dE d dG dA dA dI dJ d� dL dM d� dO dP d� dR d7 d� dS dL d d! dU d dW d d� dY d5 d� dZ d d� d[ d\ d� d] d^ d d< d_ d� dG dF d� da d3 d| d db d= dc dd dV da de d� dg dh d� di d d/ d
d d` dl d d� dm dn d� do d dV dq dr d� ds dt d� dj dv d� dx dy d� dC dv d� d{ d3 d� d| d} d� dV d| d� d7 d� dI d7 d� dY d� d� dG d� d� d< dU d� d� dh d? d
 d+ dO d� d� d d� dr d d d� d� d� d� d� dx d d d8 ds di dg d' dh dh d� dF d� d* d) d� d� d� d� d� d� dS d� d" d� d d@ d^ d� d dW d- dV d d� d� dQ dL d� d3 d- d� d� d d� d d d de dx d� d� d dA d\ d d� d] d� dG d� d d d� d d dF d d� d� d  dy d� d d# d� d$ d% d� d
 d& d� d d( d( d) d* dZ d+ d, d[ d d& d. d/ d d� d1 d2 d� d4 d5 d d7 d
d8 d d4 d9 d: d; d2 d< d= d d d> d� d@ dA d� dC dD d) d dE dO dG dA d� dI dJ d dL dM d dO dP dQ dR d7 d� dS dL dq d! dU d  dW d d_ dY d5 d* dZ d dB d[ d\ d> d] d^ d_ d< d_ d� dG dF d da d3 d d db d dc dd d� da de d dg dh d� di d d� d
d d� dl d dI dm dn d[ do d d� dq dr d� ds dt d� dj dv d� dx dy d� dC dv d� d{ d3 d] d| d} d� dV d| d� d7 d� d) d7 d� d� d� d� d dj d� d� dU d� dk dh d? d8 d+ dO d� d� d d� dr d dO d� d� d� d� d� dJ d d d� ds di d  d' dh d� d� dF d� d* d) d] d� d� d� d� d� d� d� d" dP d d@ d) d� d d� d- dV d� d� d� d dL d� d� d- d� dM d d� d� d d d dx d� d� d dA dm d d� d  d� dG d� d d d� d d d� d d� d d  dy d0 d d# d� d$ d% d d
 d& dr d d( d� d) d* d� d+ d, dh d d& d� d/ d d� d1 d2 d' d4 d5 d, d7 d
d� d d4 d d: d; d� d< d= d� d d> d� d@ dA d� dC dD d6 d dE d/ dG dA d� dI dJ dv dL dM d� dO dP d� dR d7 dT dS dL d� d! dU d� dW d d� dY d5 d� dZ d d d[ d\ d d] d^ d� d< d_ da dG dF d da d3 d� d db d� dc dd d� da de d� dg dh dU di d d7 d
d d! dl d d� dm dn de do d d: dq dr d� ds dt d� dj dv d` dx dy d dC dv d� d{ d3 d3 d| d} d� dV d| d� d7 d� d� d7 d� dd� d� d� dj d� d� dU d� d� dh d? dZ d+ dO d6 d� d d� dr d d~ d� d� d� d� d� d� d d d� ds di d� d' dh dr d� dF d� d* d) d' d� d� dV d� d� d� d� d" d� d d@ dc d� d d� d- dV d d� d� d� dL d� d� d- d� d\ d d� dT d d d[ dx d� d' d dA d� d d� d d� dG d d d d� d d dC d d� d� d  dy d� d d# d+ d$ d% d� d
 d& d� d d( d7 d) d* do d+ d, d� d d& d� d/ d d� d1 d2 d� d4 d5 d d7 d
d d d4 d� d: d; d� d< d= d� d d> d� d@ dA d� dC dD d� d dE d� dG dA d� dI dJ d� dL dM d� dO dP d� dR d7 d� dS dL d" d! dU d dW d d� dY d5 d� dZ d d� d[ d\ di d] d^ d� d< d_ d� dG dF d� da d3 dJ d db d� dc dd d� da de d� dg dh d� di d d� d
d d� dl d d dm dn dp do d d� dq dr d� ds dt d� dj dv d� dx dy d� dC dv d� d{ d3 dj d| d} d dV d| d� d7 d� d
 d7 d� dA d� d� dG d� d� d� dU d� d� dh d? d� d+ dO d� d� d d� dr d d� d� d� d� d� d� d6 d d d� ds di d� d' dh d� d� dF d� d* d) d� d� d� d� d� d� d� dY d" d� d d@ d d� d d� d- dV d� d� d� dI dL d� d d- d� d d d� d d d d' dx d� d d dA d� d d� d� d� dG d� d d d� d d dF d d� d� d  dy d d d# d� d$ d% dM d
 d& d� d d( d( d) d* d� d+ d, d� d d& d. d/ d d3 d1 d2 d d4 d5 dP d7 d
d8 d d4 d3 d: d; d@ d< d= d� d d> d� d@ dA dB dC dD d) d dE d$ dG dA d� dI dJ d� dL dM dN dO dP d� dR d7 d� dS dL dq d! dU d� dW d d dY d5 d* dZ d dj d[ d\ dj d] d^ d d< d_ dd dG dF d� da d3 d d db d� dc dd d� da de d� dg dh d� di d d� d
d d" dl d d� dm dn dm do d d� dq dr d� d? dt d& dj dv d� dx dy d� dC dv do d{ d3 d� d| d} d\ dV d| d d7 d� d� d7 d� dP d� d� dN dj d� d� dU d� db dh d? d3 d+ dO d� d� d d� dr d d d� d� d� d� d� dN d d d� ds di d� d' dh d d� dF d� d* d) d� d� d� d d� d� d� d� d" dl d d@ d� d� d d+ d- dV d� d� d� d� dL d� da d- d� dM d d� d d d d dx d� d d dA dm d d� d� d� dG d5 d d d� d d d� d d� d� d  dy d� d d# d� d$ d% d� d
 d& dS d d( d= d) d* dE d+ d, d d d& d� d/ d d d1 d2 d� d4 d5 d6 d7 d
dj d d4 dc d: d; d d< d= d7 d d> dI d@ dA d� dC dD dr d dE d� dG dA d� dI dJ d� dL dM d[ dO dP d� dR d7 d) dS dL d d! dU d� dW d d� dY d5 d� dZ d d d[ d\ d. d] d^ db d< d_ d� dG dF d9 da d3 d d db d� dc dd d� da de d� dg dh d� di d d d
d d� dl d d� dm dn de do d d� dq dr d� ds dt d� dj dv d dx dy d� dC dv dV d{ d3 d� d| d} d dV d| dX d7 d� d� d7 d� d� d� d� d� dj d� dN dU d� d� dh d? d d+ dO d3 d� d dv dr d d~ d� d� d� d� d� d� d d d� ds di d� d' dh d� d� dF d� d* d) d� d� d� dP d� d� d� d� d" d� d d@ d� d� d d� d- dV dZ d� d� d1 dL d� d d- d� du d d� d[ d d d� dx d� d\ d dA d@ d d� dT d� dG dA d d d� d d dC d d� d� d  dy d8 d d# d+ d$ d% dq d
 d& d3 d d( d d) d* d� d+ d, d^ d d& d� d/ d d� d1 d2 d� d4 d5 d d7 d
d d d4 d� d: d; d^ d< d= d� d d> d� d@ dA d� dC dD d d dE d dG dA dA dI dJ dA dL dM d� dO dP d� dR d7 d� dS dL dS d! dU d dW d dC dY d5 d5 dZ d d� d[ d\ dV d] d^ d� d< d_ d� dG dF d� da d3 d� d db d� dc dd d� da de d� dg dh d� di d d; d
d d� dl d d� dm dn dm do d dV dq dr d! ds dt d� dj dv dA dx dy dK dC dv d� d{ d3 d� d| d} d� dV d| d� d7 d� d d7 d� d� d� d� dP dj d� d� dU d� dj dh d? db d+ dO d� d� d d. dr d d� d� d� d� d� d� d� d d d� ds di d� d' dh d6 d� dF d� d* d) d� d� d� d d� d� d� d� d" d� d d@ d d� d d� d- dV d� d� d� d� dL d� d d- d� d� d d� dv d d d� dx d� d7 d dA d d d� d� d� dG d� d d d� d d d� d d� dV d  dy d� d d# d d$ d% d d
 d& d2 d d( dJ d) d* dt d+ d, d- d d& d� d/ d d d1 d2 d3 d4 d5 dq d7 d
d� d d4 d9 d: d; d� d< d= d� d d> d? d@ dA d� dC dD d� d dE dO dG dA d� dI dJ dV dL dM dN dO dP d> dR d7 d. dS dL dq d! dU d dW d dj dY d5 d� dZ d d� d[ d\ d> d] d^ dW d< d_ dF dG dF d da d3 d d db d� dc dd d da de d. dg dh d� di d d2 d
d d dl d d� dm dn d[ do d dq dq dr d� ds dt d- dj dv d4 dx dy d+ dC dv d� d{ d3 d d| d} d� dV d| d� d7 d� d` d7 d� d� d� d� d� dj d� d` dU d� d  dh d? d$ d+ dO d� d� d d� dr d dO d� d� dE d� d� d d d d� ds di d� d' dh d� d� dF d� d* d) d� d� d� dd� d� d� d� d" d� d d@ d� d� d do d- dV dO d� d� d� dL d� dO d- d� d� d d� du d d d� dx d� dV d dA dm d d� d d� dG dD d d d d d d� d d� d( d  dy d� d d# dP d$ d% dM d
 d& d4 d d( d� d) d* d� d+ d, dh d d& d� d/ d d{ d1 d2 d� d4 d5 dV d7 d
di d d4 d� d: d; dQ d< d= d< d d> d� d@ dA d
 dC dD d� d dE d dG dA d� dI dJ d� dL dM d� dO dP d� dR d7 d� dS dL d� d! dU d� dW d d� dY d5 db dZ d d� d[ d\ d� d] d^ dL d< d_ d� dG dF d� da d3 dn d db d� dc dd d da de d� dg dh d� di d d� d
d d� dl d d� dm dn d? do d d� dq dr d� ds dt dd dj dv dq dx dy d dC dv d� d{ d3 d� d| d} d� dV d| d	 d7 d� d d7 d� d d� d� d9 dj d� d� dU d� d� dh d? d d+ dO d� d� d dh dr d d~ d� d� dA d� d� d9 d d d� ds di d� d' dh d� d� dF d� d* d) d� d� d� d d� d� d� d� d" d1 d d@ d d� d d� d- dV dl d� d� d! dL d� d d- d� d| d d� d� d d d� dx d� d� d dA d d d� dT d� dG d� d d d� d d dC d d� d� d  dy d+ d d# d+ d$ d% d� d
 d& d� d d( d d) d* d7 d+ d, d� d d& d� d/ d d d1 d2 d� d4 d5 d d7 d
d� d d4 d5 d: d; d^ d< d= d� d d> d� d@ dA d� dC dD d� d dE dI dG dA dA dI dJ d� dL dM d� dO dP d� dR d7 d� dS dL dg d! dU d dW d d dY d5 dO dZ d d� d[ d\ d d] d^ d d< d_ d� dG dF df da d3 d� d db d� dc dd dV da de d� dg dh d2 di d d/ d
d d` dl d d� dm dn d� do d d� dq dr dF ds dt d� dj dv dl dx dy d dC dv d� d{ d3 d� d| d} d� dV d| d� d7 d� dU d7 d� d d� d� dG d� d� d� dU d� d� dh d? d
 d+ dO d� d� d d� dr d d d� d� d� d� d� d d d dt ds di d� d' dh dh d� dF d� d* d) d� d� d� d\ d� d� d� d� d" d d d@ d d� d dW d- dV dd� d� d� dL d� d d- d� d� d d� d/ d d de dx d� d� d dA dt d d� d
d� dG d� d d d� d d dA d d� dV d  dy dd d# d d$ d% d� d
 d& d� d d( d d) d* d� d+ d, d- d d& d� d/ d d� d1 d2 d� d4 d5 dP d7 d
d� d d4 d� d: d; dd< d= dX d d> d? d@ dA dD dC dD dj d dE d� dG dA d! dI dJ dE dL dM d� dO dP dQ dR d7 d� dS dL d� d! dU dV dW d dX dY d5 d� dZ d dB d[ d\ d� d] d^ d� d< d_ d` dG dF d da d3 d� d db d dc dd d� da de d� dg dh dJ di d d� d
d d] dl d dI dm dn dW do d d dq dr d+ ds dt d> dj dv d� dx dy d dC dv d� d{ d3 dO d| d} d~ dV d| d� d7 d� d? d7 d� d� d� d� dT dj d� d� dU d� d� dh d? d� d+ dO d> d� d d1 dr d d� d� d� d� d� d� dN d d dk ds di dd d' dh dH d� dF d� d* d) dr d� d� d� d� d� d� d� d" d� d d@ d� d� d d� d- dV d� d� d� d� dL d� d d- d� d= d d� du d d d� dx d� dn d dA dm d d� dW d� dG dZ d d dy d d d d d� d� d  dy d d d# d� d$ d% d/ d
 d& d d d( d� d) d* d� d+ d, dh d d& d� d/ d d� d1 d2 d� d4 d5 d) d7 d
dr d d4 d� d: d; de d< d= d= d d> d� d@ dA d� dC dD d� d dE d dG dA d� dI dJ di dL dM d� dO dP d= dR d7 dL dS dL d d! dU d� dW d d dY d5 d� dZ d d� d[ d\ d� d] d^ d� d< d_ d� dG dF d� da d3 d� d db d dc dd d� da de d� dg dh d di d d d
d d! dl d d� dm dn d� do d d# dq dr d� ds dt d� dj dv d` dx dy dv dC dv d d{ d3 d� d| d} d} dV d| d� d7 d� d� d7 d� ds d� d� d9 dj d� d� dU d� d� dh d? d d+ dO dP d� d d� dr d d~ d� d� d5 d� d� d$ d d dV ds di d� d' dh dM d� dF dV d* d) d d� d� df d� d� d( d� d" d� d d@ d! d� d dW d- dV d� d� d� d dL d� dI d- d� dj d d� dG d d dD dx d� d� d dA d@ d d� dK d� dG d� d d d� d d d� d d� d� d  dy d( d d# d� d$ d% d� d
 d& d� d d( d[ d) d* d� d+ d, d� d d& dB d/ d d d1 d2 d� d4 d5 d< d7 d
d d d4 d~ d: d; d� d< d= d� d d> d� d@ dA dg dC dD d� d dE d dG dA d� dI dJ d� dL dM d� dO dP d� dR d7 d� dS dL d d! dU d dW d dr dY d5 d� dZ d dL d[ d\ d� d] d^ d d< d_ d� dG dF d_ da d3 d� d db d dc dd d� da de dq dg dh dF di d d� d
d d8 dl d d� dm dn d� do d d� dq dr di ds dt d dj dv dV dx dy dK dC dv d� d{ d3 d� d| d} d� dV d| dd d7 d� d� d7 d� d� d� d� d� dj d� d� dU d� dv dh d? d� d+ dO d� d� d d� dr d d� d� d� do d� d� dx d d d ds di d^ d' dh d� d� dF d� d* d) d+ d� d� d6 d� d� d� dY d" d� d d@ d d� d d� d- dV d� d� d� dI dL d� d� d- d� do d d� d d d d' dx d� d� d dA d� d d� d d� dG d� d d d� d d d� d d� d� d  dy d� d d# d� d$ d% d� d
 d& d d d( d( d) d* da d+ d, d� d d& d. d/ d d d1 d2 de d4 d5 dP d7 d
d� d d4 dL d: d; d� d< d= d� d d> d� d@ dA d, dC dD d) d dE d1 dG dA d� dI dJ d� dL dM d0 dO dP d� dR d7 d� dS dL d� d! dU d� dW d d+ dY d5 d* dZ d d� d[ d\ d� d] d^ d d< d_ d� dG dF d da d3 d d db d� dc dd dr da de d� dg dh dJ di d d� d
d dc dl d dI dm dn d
do d d� dq dr d+ ds dt dI dj dv d� dx dy d dC dv dQ d{ d3 d� d| d} d~ dV d| d� d7 d� d" d7 d� d� d� d� dT dj d� d� dU d� d� dh d? d� d+ dO dL d� d d1 dr d d� d� d� d� d� d� dN d d d ds di d� d' dh dH d� dF d
 d* d) d� d� d� d� d� d� dB d� d" d+ d d@ dJ d� d d d- dV dg d� d� du dL d� dS d- d� d d d� du d d d� dx d� d d dA dm d d� d_ d� dG dx d d dy d d d d d� d d  dy d d d# d� d$ d% d
d
 d& d� d d( d� d) d* d� d+ d, d� d d& d� d/ d d� d1 d2 d� d4 d5 d+ d7 d
d� d d4 d� d: d; d� d< d= d� d d> d d@ dA dh dC dD d� d dE d� dG dA d� dI dJ dv dL dM d� dO dP d� dR d7 d� dS dL d� d! dU d� dW d d� dY d5 d� dZ d d d[ d\ d d] d^ d d< d_ d� dG dF d da d3 d� d db d� dc dd d� da de d` dg dh dW di d d' d
d di dl d d� dm dn d� do d d� dq dr d� ds dt d� dj dv d� dx dy d dC dv d d{ d3 d( d| d} d� dV d| d	 d7 d� d� d7 d� d d� d� d> dj d� d� dU d� d$ dh d? dm d+ dO d� d� d d dr d d d� d� dU d� d� d� d d d~ ds di d d' dh d� d� dF d� d* d) dc d� d� d� d� d� d� d� d" d� d d@ dG d� d d d� dV dN d� d� d dL d� d d- d� dG d d� dX d d d dx d� d� d dA d@ d d� d� d� dG d� d d d� d d d d d� d� d  dy do d d# d d$ d% d� d
 d& dJ d d( d+ d) d* d� d+ d, d3 d d& d� d/ d d d1 d2 d� d4 d5 d d7 d
dF d d4 d� d: d; d^ d< d= d d d> d[ d@ dA d� dC dD d� d dE da dG dA d� dI dJ d� dL dM d\ dO dP d� dR d7 d dS dL d� d! dU d� dW d d� dY d5 d� dZ d dA d[ d\ d� d] d^ dm d< d_ dA dG dF d� da d3 d� d db d8 dc dd dV da de d dg dh d� di d d/ d
d d� dl d di dm dn d$ do d d� dq dr dI ds dt d� dj dv d dx dy dz dC dv dC d{ d3 d	 d| d} d� dV d| d d7 d� d� d7 d� d� d� d� d� dj d� d dU d� dv dh d? dy d+ dO d? d� d d� dr d d} d� d� dF d� d� d] d d d  ds di d� d' dh d� d� dF d
 d* d) d d� d� d� d� d� d� d� d" d� d d@ d! d� d d- d- dV d� d� d� d� dL d� d d- d� d% d d� d d d d� dx d� d7 d dA d� d d� d� d� dG d� d d d d d du d d� d% d  dy d d d# d d$ d% d� d
 d& d' d d( dA d) d* d� dc d, d- d d& dN d/ d d8 d1 d2 d  d4 d5 d2 d7 d
dx d d4 d? d: d; dd< d= dX d d> d? d@ dA dD dC dD d� d dE dO dG dA d� dI dJ d7 dL dM d� dO dP d� dR d7 d� dS dL dq d! dU dV dW d d\ dY d5 dz dZ d dN d[ d\ d> d] d^ d d< d_ d` dG dF d� da d3 d d db d dc dd d da de dc dg dh dV di d d_ d
d dW dl d d� dm dn d� do d d: dq dr d� ds dt dZ dj dv d< dx dy d� dC dv d d{ d3 d] d| d} d\ dV d| d? d7 d� d� d7 d� d� d� d� d� dj d� d; dU d� dv dh d? d$ d+ dO d� d� d d� dr d d- d� d� d� d� d� d� d d dF ds di d� d' dh d	 d� dF d
d* d) d� d� d� d d� d� d� d� d" d� d d@ d� d� d d� d- dV d� d� d� d	 dL d� d� d- d� d� d d� dv d d d� dx d� d� d dA d d d� d< d� dG d� d d d� d d d� d d� d� d  dy d� d d# d� d$ d% dU d
 d& d d d( d= d) d* d� d+ d, dv d d& dd d/ d d� d1 d2 d� d4 d5 d6 d7 d
d� d d4 d� d: d; d` d< d= d4 d d> d� d@ dA d� dC dD d� d dE d dG dA d� dI dJ d	 dL dM dY dO dP d� dR d7 d� dS dL d d! dU d� dW d d� dY d5 d� dZ d d d[ d\ d� d] d^ dB d< d_ d2 dG dF dK da d3 da d db d� dc dd d� da de d� dg dh d di d dg d
d dQ dl d dg dm dn d# do d d� dq dr d\ ds dt d� dj dv d$ dx dy d� dC dv d] d{ d3 d3 d| d} dg dV d| dX d7 d� d� d7 d� d d� d� d� dj d� d� dU d� d� dh d? d� d+ dO dh d� d dV dr d de d� d� d� d� d� d� d d d� ds di d� d' dh d� d� dF d� d* d) d: d� d� d� d� d� dO d� d" d d d@ d d� d dd- dV d� d� d� dn dL d� d� d- d� d� d d� d� d d d" dx d� dW d dA d d d� d� d� dG d0 d d d� d d dS d d� d� d  dy d� d d# d� d$ d% dS d
 d& d� d d( dA d) d* d  d+ d, d  d d& d� d/ d d d1 d2 d d4 d5 dz d7 d
df d d4 d� d: d; dT d< d= d	 d d> d� d@ dA d� dC dD d& d dE d� dG dA dc dI dJ d^ dL dM dS dO dP d} dR d7 d� dS dL d� d! dU db d d d� dY d5 d� dZ d d� d[ d\ d� d] d^ d d< d_ d� dG dF d� da d3 d� d db d dc dd d� da de d� dg dh d� di d d~ d
d d, dl d d� dm dn d� do d d� dq dr d� ds dt d� dj dv d� dx dy d  dC dv d� d{ d3 d6 d| d} d� dV d| dA d7 d� d� d7 d� dG d� d� d} dj d� d� dU d� dK dh d? d� d+ dO d� d� d d� dr d da d� d� d� d� d� d� d d d9 ds di dc d' dh d� d� dF d� d* d) d� d� d� d, d� d� d� d� d" d d d@ dc d� d d d- dV d� d� d� d� dL d� d> d- d� d2 d d� de d d d� dx d� d d dA dw d d� d( d� dG d d d d^ d d d{ d d� d� d  dy d� d d# d� d$ d% dC d
 d& d~ d d( d� d) d* d� d+ d, d� d d& d� d/ d d� d1 d2 d} d4 d5 d� d7 d
d� d d4 d0 d: d; dK d< d= d! d d> d� d@ dA d� dC dD d< d dE d� dG dA d� dI dJ d� d� dM de dO dP d1 dR d7 d� dS dL d� d! dU d� dW d d� dY d5 d" dZ d d� d[ d\ d, d] d^ d� d< d_ d dG dF d� da d3 d: d db d6 dc dd dz d de d� dg dh dJ di d d2 d
d d- dl d d� dm dn dW do d d� dq dr d� ds dt d� dj dv d� dx dy d\ dC dv dz d{ d3 d d| d} d� dV d| d d7 d� d� d7 d� d% d� d� dR dj d� d� dU d� d� dh d? dp d+ dO d� d� d d� dr d d� d8 d� d� d� d� d� d d d1 ds di d] d' dh d7 d� dF d� d* d) d� d� d� dd d� d� d� d� d" d d d@ d_ d� d d� d- dV d� d� d� d] dL d� d% d- d� d d d� d� d d ds dx d� d� d dA dA d d� d  d� dG dw d d d d d d� d d� d d  dy d� d d# d� d$ d% d4 d
 d& d d d( dR d) d* d� d+ d, d� d d& dS d/ d dK d1 d2 d' d4 d5 d, d7 d
dv d d4 d� d: d; d` d< d= d' d d> d1 d@ dA d dC dD d7 d dE dP dG dA d� dI dJ dI dL dM d5 dO dP d. dR d7 d� dS dL d� d! dU d� dW d d| dY d5 dV dZ d d] d[ d\ d� d] d^ d� d< d_ d� dG dF dK da d3 dH d db d� dc dd d	 da de d� dg dh d� di d d� d
d dY dl d d dm dn d� do d dR dq dr d� ds dt dB dj dv dD dx dy d2 dC dv df d{ d3 d� d| d} d� dV d| dp d7 d� d' d7 d� d� d� d� d� dj d� d� dU d� d� dh d? dc d+ dO d} d� d d� dr d d� d� d� d� d� d� d d d d{ ds di d� d' dh d� d� dF d� d* d) d� d� d� dL d� d� d� d� d" d6 d d@ d� d� d ds d- dV d� d� d� d2 dL d� dW d- d� d� d d� d d d dn dx d� d� d dA d@ d d� dT d� dG d� d d d� d d d d d� d d  dy d( d d# d+ d$ d% d� d
 d& d d d( d~ d) d* di d+ d, d� d d& d� d/ d d  d1 d2 d	 d4 d5 d� d7 d
d d d4 d� d: d; d� d< d= dc d d> d� d@ dA d dC dD d� d dE dN dG dA d� dI dJ d� dL dM d9 dO dP df dR d7 d� dS dL d" d! dU d dW d d� dY d5 d� dZ d d� d[ d\ dD d] d^ d d< d_ d� dG dF d� da d3 d d db d� d+ dd d� da de d� dg dh d� di d d d
d d� dl d d� dm dn d� do d d� dq dr d8 ds dt d' dj dv d� dx dy d� dC dv db d{ d3 d� d| d} d> dV d| d� d7 d� d� d7 d� d� d� d� dG d� d� d� dU d� dv dh d? d d+ dO d d� d dQ dr d d� d� d� d� d� d� d d d d ds di dX d' dh d  d� dF dj d* d) d d� d� dX d� d� d& d� d" d! d d@ dg d� d d� d- dV d d� d� dq dL d� d( d- d� d  d d� dF d d d: dx d� d� d dA d� d d� d� d� dG d� d d d0 d d d
d d� dc d  dy d] d d# d� d$ d% d� d
 d& d/ d d( d� d) d* d� d+ d, d� d d& d� d/ d d/ d1 d2 d= d4 d5 d� d7 d
d� d d4 d d: d; d� d< d= d� d d> d
d@ dA dH dC dD d� d dE dX dG dA dT dI dJ d� dL dM d� dO dP d� dR d7 d� dS dL d� d! dU dX dW d d� dY d5 d� dZ d d d[ d\ db d] d^ d� d< d_ d
dG dF dU da d3 d� d db d� dc dd d� da de d� dg dh d� di d d2 d
d d" dl d dI dm dn d� do d d dq dr d+ ds dt d� dj dv d� dx dy d� dC dv d d{ d3 d� d| d} dG dV d| d� d7 d� d d7 d� d� d� d� dD dj d� dl dU d� dr dh d? d� d+ dO dJ d� d d� dr d dX d� d� d d� d� df d d d- ds di d� d' dh d� d� dF d� d* d) d� d� d� d{ d� d� d� d� d" dP d d@ d� d� d d� d- dV dv d� d� dm dL d� da d- d� d d d� du d d d� dx d� d d dA d� d d� d# d� dG dC d d dy d d d� d d� d� d  dy d� d d# d� d$ d% d� d
 d& d< d d( d6 d) d* d% d+ d, d� d d& d� d/ d d� d1 d2 d- d4 d5 d d7 d
dD d d4 d� d: d; d� d< d= d� d d> dR d@ dA d� dC dD d* d dE d� dG dA d� dI dJ d dL dM dT dO dP d� dR d7 d� dS dL d d! dU d� dW d d� dY d5 d� dZ d d� d[ d\ d� d] d^ dB d< d_ d� dG dF d� da d3 d� d db d dc dd d� da de d dg dh d� di d d� d
d d� dl d d� dm dn d� do d d� dq dr dr ds dt d� dj dv d� dx dy d� dC dv d d{ d3 d0 d| d} d dV d| d4 d7 d� dQ d7 d� d d� d� d� dj d� dB dU d� d� dh d? d� d+ dO de d� d d dr d d� d� d� d� d� d� dw d d d) ds di d� d' dh d� d� dF dc d* d) d# d� d� d� d� d� d� d� d" d! d d@ d� d� d df d- dV d� d� d� d� dL d� d� d- d� d� d d� dG d d d� dx d� d� d dA d d d� d, d� dG d# d d d� d d d d d� d� d  dy d] d d# d� d$ d% d d
 d& d d d( d d) d* do d+ d, d� d d& d� d/ d d� d1 d2 d d4 d5 d| d7 d
d� d d4 dm d: d; d� d< d= di d d> d� d@ dA d� dC dD d d dE dO dG dA d� dI dJ dD dL dM d dO dP d� dR d7 d� dS dL d� d! dU d� dW d d� dY d5 d� dZ d d� d[ d\ d� d] d^ d d< d_ d� dG dF d� da d3 d� d db d� dc dd dV da de d� dg dh d� di d d d
d d� dl d d� dm dn d� do d d� dq dr d� ds dt d� dj dv d� dx dy d dC dv dC d{ d3 d� d| d} d� dV d| d d7 d� d� d7 d� dm d� d� d� dj d� d� dU d� d� dh d? dX d+ dO d� d� d d� dr d d� d� d� d d� d� d� d d d ds di d� d' dh dY d� dF d� d* d) dg d� d� d� d� d� d� d� d" d� d d@ dc d� d dH d- dV d� d� d� d� dL d� dE d- d� d� d d� d5 d d d� dx d� d
 d dA d� d d� dv d� dG d^ d d d� d d dk d d� d� d  dy d� d d# d3 d$ d% d� d
 d& d d d( d� d) d* d� d+ d, d� d d& d� d/ d d- d1 d2 d\ d4 d5 d# d7 d
d@ d d4 d d: d; d� d< d= d� d d> d� d@ dA d5 dC dD d d dE dO dG dA d� dI dJ d� dL dM dg dO dP d� dR d7 d� dS dL d� d! dU d7 dW d d� dY d5 dz dZ d d� d[ d\ d> d] d^ d d< d_ d` dG dF dr da d3 d\ d db d� dc dd d da de d� dg dh d! di d d d
d d� dl d d� dm dn d do d d� dq dr dn ds dt d� dj dv d� dx dy d� dC dv d% d{ d3 d� d| d} d dV d| d� d7 d� d� d7 d� d� d� d� d� dj d� d� dU d� d: dh d? d, d+ dO d d� d d� dr d d d� d� ds d� d� dC d d dF ds di dw d' dh dH d� dF d� d* d) d� d� d� d� d� d� d� d� d" d� d d@ dx d� d d, d- dV d� d� d� d dL d� d, d- d� d d d� d� d d d� dx d� d� d dA dm d d� d� d� dG d� d d dD d d d� d d� d� d  dy dI d d# dW d$ d% dp d
 d& d� d d( d� d) d* d# d+ d, d� d d& d� d/ d d( d1 d2 d� d4 d5 dC d7 d
d. d d4 d� d: d; d� d< d= dk d d> d1 d@ dA d
dC dD d* d dE d� dG dA d� dI dJ d� dL dM d� dO dP d� dR d7 d� dS dL d� d! dU d� dW d d dY d5 dN dZ d d= d[ d\ d d] d^ d� d< d_ d� dG dF d� da d3 d� d db d� dc dd d da de dt dg dh dv di d d� d
d d^ dl d da dm dn dM do d dv dq dr d� ds dt d� dj dv dv dx dy d� dC dv d< d{ d3 d> d| d} d� dV d| d1 d7 d� d, d7 d� d� d� d� d dj d� d( dU d� d) dh d? d� d+ dO d  d� d d� dr d d	 d� d� dP d� d� d$ d d d� ds di d� d' dh dr d� dF d� d* d) d d� d� d" d� d� dm d� d" d� d d@ d. d� d d� d- dV dN d� d� d� dL d� d� d- d� d� d d� d d d d� dx d� dQ d dA dL d d� d� d� dG d d d d� d d dS d d� d� d  dy dw d d# di d$ d% d� d
 d& d d d( d~ d) d* d  d+ d, d( d d& d� d/ d d� d1 d2 d� d4 d5 dn d7 d
d3 d d4 d d: d; d� d< d= dq d d> d* d@ dA dg dC dD dd d dE d� dG dA d6 dI dJ dY dL dM d� dO dP d� dR d7 d� dS dL d� d! dU d dW d d� dY d5 d� dZ d d� d[ d\ dL d] d^ dd< d_ d3 dG dF d� da d3 d| d db d0 dc dd dj da de d% dg dh d$ di d d� d
d dd dl d d� dm dn d� do d d� dq dr d� ds dt df dj dv dE dx dy d� dC dv d d{ d3 d� d| d} d| d� d| d� d7 d� d1 d7 d� dV d� d� d� dj d� dA dU d� d dh d? d� d+ dO d� d� d d� dr d d2 d� d� dK d� d� d� d d d ds di d} d' dh d* d� dF d� d* d) d` d� d� d� d� d� di dY d" d� d d@ dt d� d d  d- dV dL d� d� dw dL d� d� d- d� d� d d� d d d d� dx d� d� d dA d� d d� db d� dG d d d d� d d d� d d� dV d  dy d d d# d� d$ d% d� d
 d& d� d d( d d) d* d$ d+ d, d� d d& d� d/ d d� d1 d2 d\ d4 d5 d� d7 d
do d d4 d� d: d; d� d< d= d d d> d d@ dA d� dC dD d d dE d dG dA d� dI dJ d dL dM d- dO dP d� dR d7 d3 dS dL dL d! dU d dW d d dY d5 d� dZ d d� d[ d\ d d] d^ d. d< d_ d dG dF dH da d3 dT d db dQ dc dd d/ da de d~ dg dh dS di d d� d
d d� dl d d dm dn d� do d d� dq dr d3 ds dt d� dj dv d4 dx dy du dC dv d� d{ d3 d  d| d} dg dV d| d� d7 d� d� d7 d� d� d� d� d� dj d� dv dU d� d9 dh d? d� d+ dO dU d� d d� dr d dO d� d� d� d� d� df d d d� ds di d5 d' dh di d� dF d^ d* d) d� d� d� d+ d� d� dL d� d" d d d@ dY d� d d� d- dV d d� d� d dL d� dv d- d� d d d� du d d d dx d� dF d dA d� d d� d4 d� dG d� d d d� d d d� d d� d d  dy d� d d# d  d$ d% d� d
 d& dE d d( d� d) d* d� d+ d, dd d& d� d/ d d� d1 d2 d{ d4 d5 d� d7 d
d� d d4 d; d: d; dd< d= d� d d> d� d@ dA d� dC dD d� d dE d� dG dA dR dI dJ dP dL dM dL dO dP dh dR d7 d� dS dL d� d! dU d] dW d d� dY d5 d dZ d d� d[ d\ d� d] d^ d� d< d_ d� dG dF dD da d3 d� d db d dc dd ds da de d� dg dh d� di d d� d
d d� dl d d� dm dn de do d d# dq dr d� ds dt d� dj dv d� dx dy d� dC dv d  d{ d3 d� d| d} d6 dV d| d\ d7 d� d� d7 d� d� d� d� d	 dj d� dh dU d� d� dh d? d4 d+ dO d� d� d d� dr d dx d� d� dm d� d� d� d d d� ds di dQ d' dh d� d� dF d� d* d) dl d� d� d� d� d� d� d� d" d� d d@ d� d� d d� d- dV d� d� d� d dL d� d� d- d� d\ d d� dG d d d� dx d� d� d dA d; d d� d& d� dG dK d d d� d d dC d d� d� d  dy d� d d# d� d$ d% d� d
 d& d� d d( d d) d* d` d+ d, d_ d d& d\ d/ d d  d1 d2 d- d4 d5 d� d7 d
d d d4 d~ d: d; d^ d< d= d� d d> d5 d@ dA d� dC dD d� d dE de dG dA dV dI dJ d� dL dM d> dO dP d� dR d7 d� dS dL d d! dU d dW d d� dY d5 d) dZ d d� d[ d\ d d] d^ d d< d_ d7 dG dF d� da d3 d� d db d dc dd d� da de dq dg dh d� di d d/ d
d d� dl d d� dm dn d� do d d� dq dr d� ds dt d� dj dv d dx dy d
 dC dv d� d{ d3 d� d| d} d dV d| da d7 d� d� d7 d� d� d� d� dG d� d� d� dU d� d� dh d? d� d+ dO d� d� d d� dr d d� d� d� d� d� d� dx d d d8 ds di d� d' dh dK d� dF d) d* d) d� d� d� d� d� d� d� d� d" d� d d@ d� d� d d� d- dV d� d� d� dI dL d� d3 d- d� d d d� dU d d d dx d� d� d dA d� d d� d� d� dG d� d d d8 d d dF d d� dV d  dy d d d# d~ d$ d% d� d
 d& d� d d( d� d) d* d� d+ d, d� d d& d. d/ d d0 d1 d2 d3 d4 d5 d� d7 d
do d d4 d� d: d; d@ d< d= d� d d> d? d@ dA dB dC dD d� d dE da dG dA d dI dJ dC dL dM d# dO dP d^ dR d7 d9 dS dL d� d! dU dJ dW d d dY d5 d* dZ d dB d[ d\ d� d] d^ d� d< d_ d` dG dF d da d3 d d db d dc dd d� da de d� dg dh dJ di d d2 d
d d dl d dS dm dn d do d d� dq dr d� ds dt d% d� dv d� dx dy d dC dv d� d{ d3 d� d| d} d dV d| dd d7 d� d� d7 d� d
 d� d� d9 dj d� d� dU d� d� dh d? d$ d+ dO d+ d� d do dr d d� d� d� d� d� d� d d d dF ds di d� d' dh dH d� dF d� d* d) d� d� d� d d� d� d~ d� d" d� d d@ d d� d d� d- dV ds d� d� dM dL d� d� d- d� d� d d� d� d d d� dx d� d� d dA dm d d� d� d� dG d� d d d� d d d� d d� d� d  dy dM d d# d� d$ d% d[ d
 d& dr d d( d7 d) d* d� d+ d, dh d d& d� d/ d d; d1 d2 d d4 d5 d, d7 d
d� d d4 d. d: d; d� d< d= d d d> d d@ dA dy dC dD d% d dE dS dG dA d� dI dJ d4 dL dM dl dO dP dz dR d7 d� dS dL d� d! dU d� dW d d� dY d5 d� dZ d d d[ d\ d d] d^ d4 d< d_ d� dG dF d_ da d3 d$ d db dl dc dd d� da de d� dg dh d� di d d7 d
d d! dl d d{ dm dn d� do d d# dq dr d� ds dt d� dj dv d� dx dy dQ dC dv dV d{ d3 d� d| d} d� dV d| do d7 d� d\ d7 d� d d� d� d� dj d� dB dU d� d
dh d? dz d+ dO d6 d� d d� dr d d~ d� d� d� d� d� dJ d d d� ds di d� d' dh dr d� dF d� d* d) dR d� d� d` d� d� d� d� d" dM d d@ dN d� d d� d- dV d� d� d� d� dL d� d_ d- d� d� d d� dG d d d� dx d� d� d dA d) d d� d� d� dG d4 d d d) d d d d d� d d  dy d9 d d# d4 d$ d% d� d
 d& d� d d( d d) d* do d+ d, d� d d& d� d/ d d, d1 d2 di d4 d5 d� d7 d
d� d d4 dp d: d; d^ d< d= d: d d> d� d@ dA dg dC dD d� d dE d dG dA dA dI dJ d dL dM dF dO dP dg dR d7 d� dS dL d� d! dU d� dW d d� dY d5 d) dZ d d� d[ d\ d d] d^ d� d< d_ d dG dF d} da d3 d� d db d� dc dd d da de d� dg dh d� di d d/ d
d d8 dl d dQ dm dn d� do d d� dq dr du ds dt d� dj dv d� dx dy ddC dv d� d{ d3 d� d| d} d� dV d| dZ d7 d� dC d7 d� d
d� d� d� dj d� d dU d� dv dh d? d
 d+ dO d� d� d d� dr d d d� d� d d� d� d' d d d8 ds di d� d' dh d� d� dF d d* d) dr d� d� d� d� d� d� d� d" d� d d@ d d� d dW d- dV d1 d� d� d& dL d� d� d- d� d� d d� do d d d� dx d� d� d dA d� d d� d] d� dG d� d d d d d dj d d� d� d  dy db d d# d` d$ d% dA d
 d& dW d d( d� d) d* d� d+ d, d� d d& d> d/ d d� d1 d2 d. d4 d5 dP d7 d
d8 d d4 d9 d: d; d� d< d= d^ d d> ds d@ dA ddC dD d d dE d� dG dA d dI dJ dC dL dM d� dO dP d dR d7 dG dS dL d� d! dU d� dW d d8 dY d5 d� dZ d d d[ d\ d$ d] d^ dX d< d_ d` dG dF d da d3 d d db d� dc dd d/ da de d� dg dh dJ di d d2 d
d d" dl d d� dm dn ddo d d� dq dr d� ds dt db dj dv d\ dx dy d) dC dv d d{ d3 d) d| d} d� dV d| d� d7 d� d? d7 d� d� d� d� d� dj d� d� dU d� d� dh d? d d+ dO d� d� d d� dr d d� d� d� d# d� d� dN d d d� ds di dJ d' dh d� d� dF d� d* d) d& d� d� d' d� d� d d� d" d� d d@ dm d� d d� d- dV ds d� d� d� dL d� d d- d� d� d d� d+ d d d� dx d� d d dA d� d d� d� d� dG d� d d dy d d dI d d� d d  dy d� d d# d� d$ d% d� d
 d& d� d d( d� d) d* d� d+ d, d" d d& d� d/ d d* d1 d2 d
 d4 d5 dq d7 d
d� d d4 d� d: d; d d< d= d� d d> d� d@ dA dG dC dD d7 d dE d� dG dA dF dI dJ db dL dM d� dO dP d� dR d7 dT dS dL d� d! dU d* dW d d_ dY d5 d9 dZ d d0 d[ d\ d� d] d^ d	 d< d_ d� dG dF d da d3 d� d db dl dc dd d� da de d� dg dh d di d d� d
d d! dl d d� dm dn de do d d� dq dr d ds dt d� dj dv d� dx dy d
 dC dv d d{ d3 d� d| d} dM dV d| d4 d7 d� d� d7 d� dR d� d� d� dj d� dB dU d� d� dh d? d d+ dO d� d� d d dr d d� d� d� dA d� d� d� d d d� ds di d� d' dh dr d� dF d� d* d) d� d� d� dE d� d� d� d� d" d6 d d@ d( d� d d� d- dV d� d� d� d� dL d� d� d- d� du d d� dT d d d� dx d� d� d dA d@ d d� d� d� dG d� d d d� d d d� d d� d� d  dy d d d# dm d$ d% d� d
 d& d? d d( d� d) d* d� d+ d, d� d d& d� d/ d d� d1 d2 d- d4 d5 d� d7 d
d� d d4 d~ d: d; d^ d< d= d: d d> d0 d@ dA dK dC dD d� d dE d dG dA dA dI dJ d dL dM d� dO dP d} dR d7 dg dS dL d d! dU d� dW d d� dY d5 d� dZ d d� d[ d\ d� d] d^ d d< d_ d� dG dF d� da d3 d" d db d dc dd d� da de dq dg dh d� di d d/ d
d d� dl d d� dm dn d3 do d d" d� dr d8 ds dt dE dj dv d� dx dy d� dC dv d� d{ d3 dI d| d} d� dV d| da d7 d� ds d7 d� d� d� d� dG d� d� d� dU d� dr dh d? d� d+ dO d� d� d d� dr d d� d� d� d1 d� d� dx d d d8 ds di d� d' dh d� d� dF de d* d) d� d� d� d6 d� d� dS d� d" d� d d@ d� d� d d� d- dV d� d� d� dI dL d� d3 d- d� dg d d� d� d d d� dx d� d� d dA d d d� d� d� dG d� d d d^ d d du d d� d� d  dy d d d# d� d$ d% d d
 d& d� d d( d d) d* dr d+ d, d� d d& d	 d/ d d� d1 d2 da d4 d5 d� d7 d
d� d d4 d� d: d; d2 d< d= d� d d> d? d@ dA d� dC dD d� d dE dO dG dA d� dI dJ d� dL dM dN dO dP d dR d7 d
dS dL d� d! dU d� dW d d� dY d5 d� dZ d d� d[ d\ d d] d^ dX d< d_ d
 dG dF d� da d3 d� d db d� dc dd d� da de df dg dh d di d d� d
d d� dl d d� dm dn d� do d d dq dr d� ds dt d- dj dv d dx dy d� dC dv db d{ d3 dO d| d} d� dV d| d� d7 d� do d7 d� dE d� d� d dj d� d dU d� d� dh d? d( d+ dO d� d� d d� dr d d� d� d� d� d� d� dL d d dR ds di d d' dh d d� dF d� d* d) d� d� d� d4 d� d� d
 d� d" dp d d@ d� d� d d
d- dV d� d� d� d" dL d� d� d- d� d� d d� dt d d dG dx d� d� d dA d d d� d d� dG d
d d do d d dJ d d� d7 d  dy dz d d# d� d$ d% d d
 d& dg d d( d{ d) d* d� d+ d, d d d& d� d/ d d� d1 d2 d� d4 d5 d d7 d
dr d d4 d� d: d; d� d< d= d6 d d> d d@ dA d dC dD da d dE d dG dA d> dI dJ da dL dM d� dO dP d� dR d7 d� dS dL d� d! dU dx dW d d~ dY d5 d� dZ d dW d[ d\ d� d] d^ d� d< d_ d dG dF d� da d3 d
 d db d� dc dd d� da de dV dg dh d� di d dd d
d d dl d d4 dm dn d do d d� dq dr d� ds dt dz dj dv dx dx dy d� dC dv d# d{ d3 d� d| d} dl dV d| d� d7 d� d d7 d� dy d� d� d9 dj d� d� dU d� d� dh d? d� d+ dO d� d� d d� dr d dP d� d� d� d� d� d3 d d d� ds di dg d' dh d' d� dF d� d* d) d d� d� d[ d� d� d� d� d" df d d@ d4 d� d d� d- dV d d� d� d� dL d� d� d- d� dS d d� d< d d d[ dx d� d� d dA d� d d� d d� dG d d d d� d d d� d d� d d  dy d= d d# dQ d$ d% d� d
 d& d3 d d( d� d) d* d| d+ d, d� d d& d� d/ d d� d1 d2 d� d4 d5 d� d7 d
d� d d4 d� d: d; d� d< d= d� d d> d� d@ dA d� dC dD d� d dE d$ dG dA dV dI dJ d& dL dM dS dO dP d� dR d7 da dS dL d� d! dU d� dW d d_ dY d5 d? dZ d d� d[ d\ d d] d^ dd< d_ d� dG dF d� da d3 d0 d db d dc dd dk da de d� dg dh d� di d dT d
d d8 dl d d� dm dn d� do d dy dq dr di ds dt d� dj dv d� dx dy d� dC dv d� d{ d3 dj d| d} d� dV d| d� d7 d� d
 d7 d� d� d� d� dG d� d� dr dU d� d� dh d? da d+ dO d� d� d d� dr d d� d� d� d� d� d� dx d d d ds di d� d' dh d� d� dF d� d* d) d� d� d� d6 d� d� d� dY d" d d d@ d d� d d� d- dV dV d� d� dI dL d� db d- d� d� d d� dM d d d dx d� dy d dA d� d d� d9 d� dG d� d d d d d d� d d� d� d  dy d d d# d� d$ d% d� d
 d& d' d d( d, d) d* d5 d+ d, d- d d& d( d/ d d0 d1 d2 d3 d4 d5 d� d7 d
d� d d4 d9 d: d; d� d� d= d� d d> d? d@ dA d dC dD d� d dE dO dG dA d� dI dJ d� dL dM dN dO dP d� dR d7 d. dS dL dq d! dU d� dW d d� dY d5 d* dZ d d� d[ d\ d d] d^ d d< d_ d� dG dF d da d3 dR d db d� dc dd d da de d� dg dh dh di d d2 d
d dZ dl d dI dm dn d[ do d d� dq dr d! ds dt d� dj dv dV dx dy d� dC dv d d{ d3 d d| d} d~ dV d| d7 d7 d� d� d7 d� d� d� d� d dj d� d� dU d� d� dh d? d� d+ dO du d� d d dr d dO d� d� dm d� d� d� d d d� ds di d� d' dh dH d� dF d� d* d) d� d� d� d: d� d� d� d� d" d� d d@ dJ d� d d+ d- dV d� d� d� dZ dL d� da d- d� d3 d d� du d d d dx d� d� d dA dk d d� d� d� dG d? d d dL d d d� d d� d@ d  dy d� d d# d� d$ d% d� d
 d& dS d d( d= d) d* dX d+ d, d4 d d& d� d/ d d� d1 d2 dI d4 d5 d6 d7 d
d� d d4 dF d: d; d d< d= d7 d d> d� d@ dA d� dC dD dr d dE du dG dA d� dI dJ d� dL dM d[ dO dP d� dR d7 d� dS dL d� d! dU d� dW d d� dY d5 d[ dZ d d d[ d\ d d] d^ db d< d_ d� dG dF d� da d3 d� d db d� dc dd d da de d� dg dh d� di d d� d
d d� dl d d� dm dn de do d d� dq dr d� ds dt d� dj dv d� dx dy dD dC dv dV d{ d3 dj d| d} d� dV d| dX d7 d� d� d7 d� d� d� d� d� dj d� dB dU d� d� dh d? d d+ dO d6 d� d d� dr d d� d� d� d� d� d� d^ d d d5 ds di d� d' dh d d� dF dM d* d) d� d� d� dV d� d� d� d� d" d� d d@ dc d� d d� d- dV d� d� d� d dL d� d0 d- d� du d d� d� d d d� dx d� d� d dA dK d d� dT d� dG d� d d d� d d dC d d� d� d  dy d� d d# d+ d$ d% dP d
 d& d� d d( d d) d* d� d+ d, d' d d& d� d/ d d� d1 d2 d� d4 d5 d d7 d
dK d d4 d d: d; d^ d< d= d� d d> d[ d@ dA d� dC dD d� d dE d� dG dA dA dI dJ d� dL dM d} dO dP d� dR d7 d� dS dL d d! dU d dW d d� dY d5 d5 dZ d d� d[ d\ dM d] d^ d� d< d_ d� dG dF d� da d3 d� d db d� dc dd d� da de d� dg dh d� di d d� d
d d  dl d d� dm dn d� do d d1 dq dr di ds dt d� dj dv d� dx dy d� dC dv d� d{ d3 dj d| d} d! dV d| d� d7 d� d
 d7 d� dL d� d� dW dj d� d� dU d� d� dh d? d� d+ dO d� d� d d� dr d d d� d� d� d� d� d6 d d d� ds di d� d' dh d� d� dF d� d* d) d� d� d� d d� d� d� d� d" d� d d@ d5 d� d d� d- dV d� d� d� dh dL d� d� d- d� d� d d� dW d9 d dS dx d� d7 d dA d d d� d� d� dG d? d d de d d dF d d� d d  dy d d d# d� d$ d% dM d
 d& d� d d( d( d) d* d� d+ d, d� d d& d. d/ d d� d1 d2 d d4 d5 dP d7 d
d� d d4 d� d: d; d� d< d= dG d d> d? d@ dA d dC dD d! d dE d� dG dA d� dI dJ dK dL dM d� dO dP d] dR d7 d� dS dL dq d! dU d� dW d d| dY d5 d* dZ d dH d[ d\ d� d] d^ dX d< d_ dc dG dF d� da d3 d� d db dN dc dd d} da de df dg dh d� di d d� d
d d� dl d dI dm dn d� do d dn dq dr d+ ds dt d dj dv d] dx dy d� dC dv d* d{ d3 dO d| d} d� dV d| d� d7 d� d( d7 d� dE d� d� d� dj d� d� dU d� d� dh d? d$ d+ dO d� d� d d� dr d dO d� d� dE d� d� d\ d d d� ds di d� d' dh d d� dF d� d* d) d$ d� d� d{ d� d� d� d� d" d� d d@ d� d� d d d- dV dO d� d� du dL d� d� d- d� dN d d� dc d d d dx d� d� d dA dm d d� d� d� dG d� d d d: d d d� d d� d� d  dy d d d# d� d$ d% d1 d
 d& d d d( d= d) d* d� d+ d, d� d d& d� d/ d d� d1 d2 d� d4 d5 d
d7 d
d� d d4 d� d: d; d` d< d= d� d d> d� d@ dA d� dC dD d* d dE d; dG dA d dI dJ d	 dL dM ddO dP d0 dR d7 d� dS dL d� d! dU dY dW d d� dY d5 dn dZ d d? d[ d\ dn d] d^ d� d< d_ d� dG dF d da d3 d� d db d� dc dd d da de d dg dh d� di d d� d
d d� dl d d dm dn d3 do d d dq dr d* ds dt do dj dv d� dx dy dV dC dv d d{ d3 d� d| d} d� dV d| dS d7 d� d� d7 d� d� d� d� d	 dj d� d� dU d� d~ dh d? d� d+ dO dh d� d d4 dr d d~ d� d� d� d� d� d� d d d[ ds di d� d' dh dQ d� dF d� d* d) dR d� d� d d� d� d� d� d" d� d d@ d� d� d d d- dV d� d� d� d� dL d� d} d- d� d d d� d� d d dr dx d� dK d dA d� d d� dq d� dG d� d d d� d d d d d� dY d  dy dt d d# d+ d$ d% d� d
 d& d� d d( d� d) d* do d+ d, d� d d& d� d/ d d� d1 d2 d� d4 d5 dE d7 d
d d d4 d~ d: d; d^ d< d= d� d d> d� d@ dA d� dC dD d� d dE d dG dA d� dI dJ d7 dL dM d� dO dP d� dR d7 d� dS dL d� d! dU dh dW d d� dY d5 d� dZ d dA d[ d\ dV d] d^ d d< d_ d� dG dF d� da d3 de d db db dc dd d{ da de dk dg dh d� di d d/ d
d d8 dl d d� dm dn d� do d d dq dr dY ds dt d� dj dv dE dx dy d� dC dv dF d{ d3 dj d| d} d� dV d| d� d7 d� d� d7 d� d d� d� d� dj d� d� dU d� d� dh d? d� d+ dO d� d� d d� dr d d d� d� d� d� d� d� d d d ds di dw d' dh dN d� dF d� d* d) d� d� d� d� d� d� d d� d" dz d d@ dU d� d d� d- dV d8 d� d� dw dL d� d� d- d� d  d d� d� d d d� dx d� d d dA d� d d� dr d� dG dQ d d d� d d d� d d� d� d  dy d� d d# d` d$ d% d� d
 d& d~ d d( d� d) d* d� d+ d, d@ d d& d� d/ d d� d1 d2 d� d4 d5 d� d7 d
dV d d4 d� d: d; d� d< d= d d d> d d@ dA d8 dC dD d� d dE d^ dG dA d^ dI dJ d� dL dM d dO dP d dR d7 d� dS dL dK d! dU dV dW d d dY d5 d* dZ d dd d[ d\ d� d] d^ d d< d_ d` dG dF d da d3 dj d db d� dc dd dV da de d� dg dh d� di d d d
d d� dl d d� dm dn d{ do d d� dq dr d� ds dt dY dj dv d+ dx dy d� dC dv d� d{ d3 d� d| d} d� dV d| d� d7 d� d� d7 d� d� d� d� dK dj d� dt dU d� d� dh d? d� d+ dO d� d� d d� dr d d0 d� d� d� d� d� d� d d de ds di dk d' dh d8 d� dF dk d* d) d� d� d� d d� d� d� d� d" d, d d@ dY d� d d� d- dV db d� d� d. dL d� d� d- d� d d d� d� d d d� dx d� d� d dA d� d d� d� d� dG d� d d d� d d db d d� d d  dy dM d d# d� d$ d% dG d
 d& d� d d( d" d) d* d� d+ d, dS d d& d� d/ d d� d1 d2 dE d4 d5 d d7 d
d| d d4 dm d: d; d d< d= d� d d> d� d@ dA d� dC dD d� d dE d8 dG dA df dI dJ d� dL dM dz dO dP d dR d7 d� dS dL d� d! dU d� dW d dc dY d5 d� dZ d d[ d[ d\ dz d] d^ d d< d_ d, dG dF d� da d3 d+ d db d% dc dd d. da de dE dg dh d di d dH d
d d� dl d d� dm dn d� do d d� dq dr d ds dt d* dj dv d` dx dy d dC dv dV d{ d3 d� d| d} d6 dV d| dS d7 d� d� d7 d� d� d� d� ddj d� de dU d� d� dh d? d� d+ dO d� d� d da dr d d� d� d� dm d� d� d� d d d� ds di d� d' dh dY d� dF dA d* d) d� d� d� d� d� d� d, d� d" d� d d@ d[ d� d d� d- dV d� d� d� d dL d� d� d- d� dS d d� dG d d d� dx d� d� d dA d
d d� d� d� dG d� d d d� d d dC d d� d� d  dy d( d d# d4 d$ d% d� d
 d& d� d d( d d) d* do d+ d, d� d d& dj d/ d d| d1 d2 di d4 d5 dR d7 d
d( d d4 d� d: d; d� d< d= d: d d> d� d@ dA d� dC dD d� d dE dl dG dA dA dI dJ d dL dM d� dO dP d� dR d7 d& dS dL d d! dU d dW d d� dY d5 d� dZ d d= d[ d\ d� d] d^ d d< d_ d� dG dF d da d3 d d db d� dc dd dV da de dq dg dh d� di d dH d
d d8 dl d d� dm dn d� do d d dq dr d~ ds dt d� dj dv d� dx dy dK dC dv d d{ d3 dd| d} d� dV d| d� d7 d� d
 d7 d� d� d� d� dx dj d� d� dU d� dv dh d? d
 d+ dO d� d� d d� dr d d d� d� d� d� d� dx d d d� ds di d� d' dh d� d� dF d� d* d) d� d� d� d� d� d� d� d� d" d� d d@ d d� d dW d- dV d� d� d� dH dL d� d3 d- d� d� d d� d d d d+ dx d� d� d dA d� d d� d] d� dG d� d d dJ d d d� d d� dV d  dy d d d# d� d$ d% d� d
 d& d@ d d( d( d) d* d d+ d, d- d d& d d/ d d d1 d2 d3 d4 d5 dP d7 d
d8 d d4 d0 d: d; d� d< d= d9 d d> dm d@ dA d� dC dD d d dE d� dG dA d
dI dJ d� dL dM d� dO dP d dR d7 d� dS dL d� d! dU d~ dW d dM dY d5 d� dZ d da d[ d\ d> d] d^ d d< d_ d` dG dF df da d3 d� d db d� dc dd d da de dA dg dh d� di d d� d
d d# dl d d� dm dn d� do d d� dq dr d� ds dt d� dj dv d� dx dy d� dC dv d� d{ d3 d� d| d} d~ dV d| d� d7 d� dc d7 d� d� d� d� d� dj d� d� dU d� d� dh d? d� d+ dO d  d� d d� dr d d� d� d� d6 d� d� d� d d d1 ds di d d' dh d� d� dF d� d* d) d� d� d� d d� d� d$ d� d" dP d d@ d� d� d d+ d- dV d d� d� d� dL d� da d- d� d d d� du d d d) dx d� d d dA dm d d� d� d� dG d� d d d� d d dS d d� d� d  dy d� d d# dP d$ d% d d
 d& d d d( d= d) d* d� d+ d, d� d d& d� d/ d d� d1 d2 d� d4 d5 d6 d7 d
d~ d d4 d� d: d; d d< d= d� d d> d� d@ dA d dC dD d� d dE d dG dA d� dI dJ dv dL dM d� dO dP d@ dR d7 d dS dL d� d! dU d� dW d dC dY d5 d� dZ d d� d[ d\ d� d] d^ dS d< d_ d� dG dF d da d3 d� d db d� dc dd d� da de d� dg dh d di d d� d
d d dl d dj dm dn d� do d d� dq dr d\ ds dt d: dj dv d� dx dy d� dC dv d] d{ d3 d� d| d} dl dV d| dX d7 d� d� d7 d� d� d� d� d# dj d� dB dU d� d� dh d? d d+ dO d6 d� d dh dr d d� d� d� d5 d� d� d( d d d� ds di d� d' dh d� d� dF d� d* d) d! d� d� dn d� d� dh d� d" d� d d@ d� d� d d� d- dV d� d� d� d� dL d� d0 d- d� d] d d� d\ d d d	 dx d� d� d dA d� d d� d d� dG d" d d d� d d d� d d� d d  dy dD d d# d8 d$ d% d� d
 d& dh d d( d= d) d* d d+ d, d� d d& d6 d/ d d9 d1 d2 d� d4 d5 d d7 d
d� d d4 d. d: d; d� d< d= da d d> d d@ dA d� dC dD d� d dE d dG dA d� dI dJ d� dL dM d� dO dP d% dR d7 dZ dS dL d d! dU d dW d d� dY d5 d� dZ d d� d[ d\ d� d] d^ d d< d_ dR dG dF d� da d3 d� d db d� dc dd d� da de dq dg dh d� di d d/ d
d d� dl d dL dm dn d� do d d� dq dr di ds dt d� dj dv d� dx dy dK dC dv d d{ d3 d� d| d} d� dV d| d d7 d� d� d7 d� d� d� d� d� dj d� d dU d� dv dh d? d d+ dO d� d� d d� dr d d4 d� d� d� d� d� dx d d da ds di d� d' dh d� d� dF d� d* d) d� d� d� d6 d� d� d� d� d" d� d d@ d d� d d d- dV dZ d� d� dI dL d� d� d- d� d� d d� d d d d� dx d� d� d dA d� d d� d� d� dG du d d d d d dn d d� dV d  dy d d d# d� d$ d% d| d
 d& d' d d( d( d) d* d3 d+ d, d- d d& d. d/ d d� d1 d2 d� d4 d5 dP d7 d
d@ d d4 d d: d; d2 d< d= dU d d> d= d@ dA dB dC dD d� d dE d� dG dA d� dI dJ d� dL dM dN dO dP dQ dR d7 d� dS dL d d! dU dV dW d dK dY d5 d� dZ d d� d[ d\ d> d] d^ dr d< d_ dd dG dF d  da d3 d d db d� dc dd d� da de d� dg dh d� di d d� d
d dk dl d d� dm dn d� do d d� dq dr d" ds dt d� dj dv d� dx dy d$ dC dv d� d{ d3 d� d| d} dv dV d| d d7 d� d� d7 d� d� d� d� d� dj d� d� dU d� dr dh d? d� d+ dO d� d� d d6 dr d dx d� d� d� d� d� d� d d d( ds di dJ d' dh d� d� dF d{ d* d) d� d� d� d� d� d� d2 d� d" dP d d@ d_ d� d d< d- dV dO d� d� d� dL d� d� d- d� d d d� d! d d d dx d� d_ d dA d d d� d� d� dG d� d d d� d d d� d d� d d  dy d d d# d� d$ d% d� d
 d& dg d d( d= d) d* d d+ d, d� d d& d� d/ d dz d1 d2 dN d4 d5 d� d7 d
d� d d4 d; d: d; d) d< d= d� d d> d d@ dA d� dC dD d� d dE d dG dA d� dI dJ d  dL dM d� dO dP d� dR d7 dR dS dL d d! dU ddW d d- dY d5 d� dZ d do d[ d\ d  d] d^ d� d< d_ d dG dF d da d3 d
 d db de dc dd d� da de d� dg dh dd di d d' d
d d! dl d d� dm dn d� do d d� dq dr d
 ds dt d� dj dv d` dx dy d dC dv dY d{ d3 d� d| d} d� dV d| dX d7 d� d� d7 d� d d� d� d� dj d� d dU d� d� dh d? d d+ dO d6 d� d dj dr d d� d� d� d� d� d� d� d d d; ds di d, d' dh d` d� dF dM d* d) d� d� d� dV d� d� d� d� d" d� d d@ d� d� d dd- dV d{ d� d� dN dL d� d. d- d� d� d d� dG d d d� dx d� dA d dA d� d d� dT d� dG d� d d d� d d d� d d� d� d  dy d( d d# d+ d$ d% d� d
 d& d� d d( d� d) d* d d+ d, d� d d& d� d/ d d� d1 d2 d� d4 d5 d d7 d
d d d4 d~ d: d; d� d< d= d� d d> dH d@ dA d� dC dD d( d dE d� dG dA d dI dJ dG dL dM d� dO dP d� dR d7 d� dS dL d� d! dU d� dW d d_ dY d5 d9 dZ d d� d[ d\ d� d] d^ d� d< d_ d� dG dF d� da d3 d| d db d� dc dd d` da de d� dg dh d( di d d d
d d
dl d d� dm dn dS do d d� dq dr d� ds dt d� dj dv d� dx dy d� dC dv d� d{ d3 d� d| d} d� dV d| d� d7 d� dG d7 d� d| d� d� dY dj d� d� dU d� d dh d? d� d+ dO dQ d� d d� dr d d� d� d� d� d� d� d: d d d� ds di d� d' dh d� d� dF d� d* d) dI d� d� d5 d� d� d_ d� d" d� d d@ dc d� d dW d- dV d� d� d� dI dL d� d� d� d� d� d d� d� d d d� dx d� d� d dA dw d d� d� d� dG d� d d dY d d d d d� d d  dy da d d# d� d$ d% d+ d
 d& d d d( d d) d* dE d+ d, db d d& d� d/ d d� d1 d2 d� d4 d5 dY d7 d
d� d d4 d d: d; d� d< d= d! d d> d6 d� dA d� dC dD d� d dE d� dG dA d dI dJ d� dL dM d� dO dP d� dR d7 d� dS dL dq d! dU dV dW d d� dY d5 d� dZ d dB d[ d\ d> d] d^ d d< d_ d� dG dF d� da d3 d d db d dc dd d da de d� dg dh d di d d2 d
d d" dl d dI dm dn d� do d d dq dr d� ds dt d dj dv d� dx dy d� dC dv d� d{ d3 d� d| d} dR dV d| d� d7 d� dc d7 d� d� d� d� d� dj d� d� dU d� d� dh d? d� d+ dO d  d� d d� dr d d� d� d� d� d� d� dK d d dF ds di d� d' dh d� d� dF d{ d* d) d� d� d� d� d� d� d� d� d" d� d d@ d| d� d de d- dV d� d� d� d` dL d� d� d- d� dM d d� d� d d ddx d� d� d dA dm d d� d� d� dG dw d d dj d d dt d d� d= d  dy d� d d# d� d$ d% d� d
 d& d� d d( d d) d* d� d+ d, d} d d& d� d/ d d5 d1 d2 d� d4 d5 d6 d7 d
d� d d4 d[ d: d; d� d< d= d� d d> d� d@ dA d� dC dD d� d dE d/ dG dA d� dI dJ dv dL dM d� dO dP d� dR d7 d dS dL d d! dU d� dW d d� dY d5 d� dZ d d0 d[ d\ dm d] d^ d� d< d_ d� dG dF d da d3 d� d db d� dc dd dh da de d dg dh dm di d d� d
d d� dl d d� dm dn d� do d d dq dr d� ds dt d� dj dv d` dx dy dR dC dv d d{ d3 d� d| d} dM dV d| d d7 d� d� d7 d� d� d� d� d� dj d� dM dU d� do dh d? d d+ dO d6 d� d d� dr d d� d� d� d� d� d� db d d d% ds di d� d' dh dr d� dF d� d* d) d d� d� d, d� d� d� d� d" d� d d@ dc d� d d� d- dV d d� d� d1 dL d� d d- d� d� d d� dG d d d8 dx d� d� d dA d� d d� dh d� dG d d d d� d d dS d d� d� d  dy d� d d# d� d$ d% d� d
 d& d� d d( d d) d* dS d+ d, d� d d& d0 d/ d d  d1 d2 d` d4 d5 dT d7 d
db d d4 d d d; d� d< d= d� d d> d� d@ dA d
 dC dD d� d dE dr dG dA d
 dI dJ d� dL dM d� dO dP d� dR d7 d� dS dL d d! dU d
 dW d dP dY d5 d� dZ d d� d[ d\ d� d] d^ d d< d_ d� dG dF d� da d3 d� d db d� dc dd dt da de d� dg dh d� di d dd d
d dg dl d d� dm dn d� do d d� dq dr d� ds dt ddj dv d� dx dy d dC dv d� d{ d3 d d| d} d� dV d| d_ d7 d� d� d7 d� d� d� d� dG d� d� d� dU d� d" dh d? d
 d+ dO d� d� d d� dr d d� d� d� d� d� d� dx d d d8 ds di d d' dh d� d� dF d� d* d) d� d� d� dk d� d� d� d� d" d d d@ d d� d dW d- dV d� d� d� d� dL d� d3 d- d� d; d d� dM d d de dx d� d� d dA d� d d� d] d� dG d� d d d� d d dF d d� d d  dy d� d d# d� d$ d% d� d
 d& d� d d( d( d) d* dz d+ d, d� d d& d. d/ d d� d1 d2 d� d4 d5 dP d7 d
dd d4 d{ d: d; d2 d< d= d d d> d� d@ dA dB dC dD d� d dE dW dG dA d� dI dJ d� dL dM d� dO dP dQ dR d7 d� dS dL d� d! dU dV dW d d� dY d5 d dZ d d� d[ d\ d> d] d^ de d< d_ d� dG dF d da d3 d� d db d< dc dd d da de d[ dg dh dJ di d d2 d
d dZ dl d d� dm dn d[ do d d� dq dr d# ds dt d� dj dv dc dx dy d� dC dv d� d{ d3 d d| d} d� dV d| d� d7 d� d� d7 d� d� d� d� d� dj d� dC dU d� d� dh d? d$ d+ dO d� d� d d` dr d dO d� d� d. d� d� d d d d� ds di d� d' dh d� d� dF d� d* d) d� d� d� d d� d� d� d� d" dl d d@ d� d� d d+ d- dV d� d� d� d
dL d� d d- d� d d d� dd d d dx d� d� d dA d] d d� d� d� dG d� d d d� d d d� d d� d� d  dy dH d d# d9 d$ d% d d
 d& dr d d( d< d) d* d� d+ d, d� d d& d0 d/ d d� d1 d2 d� d4 d5 d� d7 d
d� d d4 d� d: d; dJ d< d= d� d d> dg d@ dA d  dC dD d� d dE dW dG dA d dI dJ dv dL dM d� dO dP d� dR d7 d� dS dL d? d! dU d� dW d d� dY d5 d� dZ d d� d[ d\ d d] d^ d� d< d_ d� dG dF d da d3 d d db d	 dc dd d� da de d� dg dh d� di d d7 d
d dh dl d d dm dn de do d d� dq dr d� ds dt d� dj dv dg dx dy d� dC dv dV d{ d3 d� d| d} dg dV d| dX d7 d� d! d7 d� dz d� d� d, dj d� dB dU d� d� dh d? di d+ dO d6 d� d d dr d d� d� d� d� d� d� d� d d d7 ds di d� d' dh d� d� dF d� d* d) d d� d� dQ d� d� dh d� d" d� d d@ dm d� d d� d- dV d� d� d� d� dL d� d� d- d� d� d d� d: d d d	 dx d� d� d dA dN d d� d7 d� dG d� d d d� d d d� d d� d� d  dy d� d d# di d$ d% d� d
 d& d� d d( d" d) d* dW d+ d, d� d d& d� d/ d d� d� d2 d� d4 d5 d< d7 d
dS d d4 d~ d: d; dj d< d= d� d d> dP d@ dA d� dC dD d� d dE d� dG dA d� dI dJ d dL dM d� dO dP di dR d7 d� dS dL d{ d! dU d~ dW d d� dY d5 d� dZ d d d[ d\ dW d] d^ d d< d_ d, dG dF d� da d3 d� d db d� dc dd d� da de d dg dh d� di d d� d
d dB dl d d� dm dn d� do d d_ dq dr di ds dt d] dj dv d� dx dy dK dC dv du d{ d3 dg d| d} d� dV d| dd d7 d� d
 d7 d� d� d� d� dP dj d� dM dU d� d� dh d? d d+ dO d� d� d d8 d� d d d� d� d� d� d� d� d d d� ds di d\ d' dh d� d� dF d� d* d) d+ d� d� d� d� d� dr d� d" d� d d@ d� d� d d d� dV d� d� d� d7 dL d� d� d- d� d� d d� dM d d d dx d� d! d dA dR d d� d d� dG d� d d d8 d d du d d� d? d  dy d d d# d� d$ d% d� d
 d& d' d d( d� d) d* dP d+ d, d[ d d& d� d/ d d� d1 d2 d d4 d5 d! d7 d
dx d d4 d9 d: d; d� d< d= ds d d> d? d@ dA dB dC dD dD d dE dv dG dA d� dI dJ d� dL dM dN dO dP dQ dR d7 d� dS dL dy d! dU d dW d d dY d5 d* dZ d dB d[ d\ d^ d] d^ d� d< d_ d` dG dF d da d3 d d db d� dc dd d da de d. dg dh d� di d d� d
d d� dl d d� dm dn ddo d d� dq dr d� ds dt db dj dv d� dx dy d� dC dv d� d{ d3 d, d| d} d� dV d| dN d7 d� d� d7 d� dz d� d� dc dj d� dv dU d� dk dh d? d� d+ dO d� d� d d� dr d dY d� d� d� d� d� dN d d d� ds di d� d' dh dW d� dF d� d* d) d� d� d� d� d� d� d� d� d" dz d d@ d� d� d dx d- dV dv d� d� dI dL d� d% d- d� di d d� d� d d d� dx d� d� d dA dY d d� dk d� dG d� d d d� d d d� d d� d� d  dy d� d d# d� d$ d% d= d
 d& d d d( d� d) d* d� d+ d, dr d d& dd d/ d d� d1 d2 d� d4 d5 d� d7 d
d� d d4 dT d: d; dB d< d= d1 d d> d� d@ dA dV dC dD d d dE d. dG dA dt dI dJ d� dL dM d! dO dP d% dR d7 d  dS dL d� d! dU d� dW d d( dY d5 dG dZ d dh d[ d\ d� d] d^ dz d< d_ d� dG dF d da d3 d� d db d� dc dd d� da de d� dg dh d� di d d7 d
d d� dl d d� dm dn d� do d dv dq dr d* ds dt d0 dj dv dD dx dy dR dC dv d� d{ d3 d& d| d} d� dV d| d� d7 d� d� d7 d� d� d� d� d� dj d� d� dU d� d dh d? d� d+ dO d4 d� d d5 dr d dF d� d� d{ d� d� d7 d d d] ds di d� d' dh d� d� dF d( d* d) d d� d� d` d� d� d� d� d" d d d@ d0 d� d d d- dV d� d� d� d dL d� d d- d� d� d d� d� d d d� dx d� d d dA d@ d d� dT d� dG d� d d d~ d d d� d d� d� d  dy d& d d# d� d$ d% d� d
 d& d� d d( d d) d* d� d+ d, d� d d& d� d/ d d� d1 d2 d
d4 d5 d� d7 d
d d d4 d� d: d; d d< d= d� d d> dT d@ dA d{ dC dD d� d dE d� dG dA d	 dI dJ d dL dM d� dO dP dy dR d7 d� dS dL d� d! dU d� dW d d^ d� d5 d  dZ d dW d[ d\ d� d] d^ dC d< d_ dm dG dF d� da d3 d� d db d� dc dd d� da de d� dg dh d6 di d dv d
d d� dl d d_ dm dn d� do d d� dq dr dM ds dt d� dj dv d� dx dy dK dC dv d� d{ d3 d� d| d} d� dV d| d� d7 d� d
 d7 d� d� d� d� d{ dj d� d� dU d� dv dh d? d
 d+ dO d� d� d d� dr d d d� d� d� d� d� dx d d d� ds di d� d' dh d� d� dF d� d* d) d� d� d� d� d� d� dE d� d" d� d d@ d d� d dW d- dV d� d� d� d dL d� d3 d- d� d� d d� d d d d+ dx d� dF d dA d� d d� d] d� dG d� d d dJ d d d� d d� dV d  dy d d d# d� d$ d% d0 d
 d& dj d d( d( d) d* d d+ d, d- d d& d� d/ d d� d1 d2 d3 d4 d5 dP d7 d
d8 d d4 dv d: d; dB d< d= d� d d> d? d@ dA dB dC dD d� d dE d^ dG dA d� dI dJ d� dL dM dN dO dP d� dR d7 d; dS dL dq d! dU dV dW d d dY d5 d dZ d d2 d[ d\ d> d] d^ d d< d_ d` dG dF d� da d3 d
 d db d dc dd d da de d� dg dh d� di d d d
d d� dl d dc dm dn dW do d d� dq dr d+ ds dt d� dj dv d� dx dy d� dC dv d� d{ d3 dc d| d} d� dV d| d� d7 d� dc d7 d� d� d� d� d� dj d� d� dU d� d� dh d? d� d+ dO dJ d� d d� dr d d� d� d� d� d� d� d d d d ds di dJ d' dh dH d� dF d� d* d) d� d� d� d d� d� d� d� d" dP d d@ d� d� d dM d- dV d� d� d� du dL d� da d- d� d d d� d� d d dt dx d� d� d dA dm d d� d� d� dG d� d d d� d d dI d d� d� d  dy d� d d# d� d$ d% d d
 d& d d d( d= d) d* d� d+ d, d} d d& d4 d/ d d d1 d2 d� d4 d5 d6 d7 d
d� d d4 d d: d; d� d< d= d d d> d� d@ dA dd dC dD d d dE d2 dG dA d� dI dJ d� dL dM d dO dP d� dR d7 d� dS dL d d! dU d� dW d d� dY d5 d[ dZ d d d[ d\ d d] d^ d� d< d_ d dG dF d� da d3 d� d db d dc dd dh da de d� dg dh dm di d d� d
d d	 dl d d  dm dn d� do d dR dq dr d� ds dt d� dj dv d` dx dy d dC dv dV d{ d3 d� d| d} d� dV d| d� d7 d� d  d7 d� dR d� d� d� dj d� dB dU d� d� dh d? d d+ dO d� d� d d� dr d dO d� d� d� d� d� d� d d d> ds di d� d' dh dr d� dF d� d* d) d� d� d� d` d� d� d� d� d" d1 d d@ d� d� d d� d- dV d� d� d� d dL d� d� d- d� dL d d� db d d d dx d� d� d dA d) d d� d� d� dG d� d d d� d d dC d d� d� d  dy d( d d# d� d$ d% d� d
 d& d� d d( d d) d* do d+ d, d� d d& d� d/ d d� d1 d2 d� d4 d5 d d7 d
dZ d d4 d� d: d; d& d< d= d	 d d> d, d@ dA d� dC dD d� d dE d� dG dA d� dI dJ d� dL dM d� dO dP d� dR d7 d� dS dL d� d! dU dZ dW d d� dY d5 d� dZ d d d[ d\ dV d] d^ d� d< d_ d dG dF d� da d3 d� d db d� dc dd dV da de d� dg dh dg di d d/ d
d d8 dl d d� dm dn d� do d d� dq dr dX ds dt d� dj dv d� d� dy d dC dv d� d{ d3 d� d| d} d� dV d| d% d7 d� d� d7 d� d0 d� d� de dj d� d dU d� d� dh d? da d+ dO d� d� d d dr d dI d� d� d� d� d� d� d d dt ds di d� d' dh dh d� dF dq d* d) d� d� d� de d� d� d d� d" dn d d@ d; d� d d� d- dV dV d� d� d� dL d� d� d- d� d d d� dh d d d dx d� d! d dA d� d d� d� d� dG d� d d d� d d dD d d� d� d  dy d� d d# d d$ d% d5 d
 d& d� d d( d� d) d* d d+ d, d- d d& d. d/ d d0 d1 d2 d� d4 d5 dP d7 d
d8 d d4 d9 d: d; d� d< d= d� d d> d? d@ dA dB dC dD de d dE dO dG dA d� dI dJ d� dL dM d� dO dP d� dR d7 d� dS dL dq d! dU dV dW d d� dY d5 d� dZ d d� d[ d\ d$ d] d^ d d< d_ d` dG dF d� da d3 d� d db d� dc dd d- da de d% dg dh d� di d d� d
d dk dl d dI dm dn ddo d d dq dr d+ ds dt d dj dv d dx dy d dC dv d d{ d3 d� d| d} d~ dV d| d� d7 d� d� d7 d� d� d� d� d� dj d� d� dU d� d� dh d? dp d+ dO d� d� d d� dr d dh d� d� dY d� d� dN d d dF ds di d� d' dh dH d� dF d� d* d) d� d� d� d� d� d� d
 d� d" d� d d@ dK d� d d� d- dV d d� d� dm dL d� da d- d� d� d d� du d d d dx d� d� d dA d3 d d� d� d� dG d� d d dp d d d� d d� d= d  dy d� d d# d� d$ d% d@ d
 d& d d d( d= d) d* d� d+ d, dv d d& d� d/ d d� d1 d2 d� d4 d5 d2 d7 d
d� d d4 d� d: d; d d< d= d� d d> d> d@ dA d7 dC dD d� d dE d. dG dA d� dI dJ d� dL dM d	 dO dP d dR d7 d� dS dL d� d! dU d� dW d d� dY d5 d@ dZ d dT d[ d\ d d] d^ d� d< d_ d� dG dF d da d3 d� d db d� dc dd d� da de d� dg dh d[ di d d7 d
d dh dl d d� dm dn de do d d{ dq dr d� ds dt d� dj dv d dx dy d dC dv dV d{ d3 dg d| d} d� dV d| dX d7 d� d� d7 d� d� d� d� d� dj d� dM dU d� d� dh d? d d+ dO dm d� d d� dr d d~ d� d� d, d� d� d3 d d d� ds di d� d' dh d� d� dF d� d* d) d� d� d� d[ d� d� d� d� d" d d d@ d� d� d d� d- dV d� d� d� dp dL d� d d- d� d� d d� d� d d d� dx d� d\ d dA dH d d� dT d� dG d� d d d� d d dC d d� d d  dy dD d d# d+ d$ d% d� d
 d& d� d� d( d d) d* d� d+ d, d' d d& d� d/ d d� d1 d2 d> d4 d5 d d7 d
ds d d4 d� d: d; d^ d< d= dL d d> d] d@ dA d dC dD d� d dE d� dG dA dA dI dJ d dL dM d� dO dP d� dR d7 d� dS dL d� d! dU d� dW d d dY d5 dv dZ d d� d[ d\ dn d] d^ d d< d_ d� dG dF d� da d3 d� d db d= dc dd d da de d0 dg dh d� di d d; d
d da dl d d� dm dn d� do d d� dq dr di ds dt d� dj dv d� dx dy dK dC dv d d{ d3 d d| d} d� dV d| d d7 d� d� d7 d� d� d� d� d� dj d� d dU d� dv dh d? dE d+ dO d� d� d d� dr d d� d� d� d	 d� d� dx d d dC ds di d� d' dh d� d� dF d d* d) d� d� d� d6 d� d� d� d� d" dA d d@ d d� d d� d- dV d� d� d� dI dL d� db d- d� d� d d� d d d d' dx d� d d dA d� d d� d\ d� dG d� d d d� d d d� d d� dV d  dy d d d# d� d$ d% d d
 d& d� d d( de d) d* d d+ d, d7 d d& d. d/ d d0 d1 d2 db d4 d5 d" d7 d
dx d d4 d� d: d; d� d< d= d� d d> d d@ dA d� dC dD d) d dE dU dG dA d� dI dJ d� dL dM d dO dP d dR d7 d� dS dL d! d! dU d} dW d d dY d5 d� dZ d d# d[ d\ d> d] d^ de d< d_ d� dG dF d da d3 d� d db d< dc dd d da de dc dg dh d: di d d� d
d d# dl d d� dm dn d[ do d dL dq dr dw ds dt d� dj dv dv dx dy d� dC dv d� d{ d3 d� d| d} d� dV d| d� d7 d� d� d7 d� d� d� d� d� dj d� d� dU d� dl dh d? d( d+ dO d� d� d d� dr d dO d� d� d� d� d� d6 d d d� ds di df d' dh dH d� dF d� d* d) d� d� d� d� d� d� d: d� d" d� d d@ d� d� d d+ d- dV d� d� d� d� dL d� d3 d- d� d d d� du d d d	 dx d� d d dA d� d d� d� d� dG d� d d d d� d d� d d� d d  dy d� d d# d� d$ d% d@ d
 d& d d d( d= d) d* d� d+ d, dv d d& dF d/ d dv d1 d2 d� d4 d5 d6 d7 d
d� d d4 d� d: d; d� d< d= d� d d> d> d@ dA d6 dC dD d� d dE d. dG dA dn dI dJ d� dL dM d� dO dP dd dR d7 d� dS dL d� d! dU d� dW d d� dY d5 d dZ d dD d[ d\ d� d] d^ d� d< d_ d dG dF d da d3 d d db d� dc dd d� da de d dg dh d� di d d7 d
d d dl d d� dm dn de do d d� dq dr d� ds dt d� dj dv d dx dy dD dC dv dV d{ d3 dg d| d} d� dV d| dX d7 d� d� d7 d� d� d� d� d9 dj d� d� dU d� d dh d? d d+ dO d� d� d d� dr d d d� d� d$ d� d� d3 d d d� ds di d� d' dh dr d� dF d� d* d) d� d� d� dV d� d� d� d� d" d� d d@ dc d� d d� d- dV d� d� d� d� dL d� d� d- d� d\ d d� dG d d dN dx d� d` d dA d@ d d� d� d� dG d d d d� d d d� d d� d� d  dy d( d d# dS d$ d% d� d
 d& d� d d( d� d) d* d� d+ d, d� d d& d� d/ d d� d1 d2 d� d4 d5 dT d7 d
d� d d4 d� d: d; d� d< d= d d d> d� d@ dA d� dC dD d� d dE d� dG dA d� dI dJ d� dL dM d" dO dP d� dR d7 d� dS dL d  d! dU d� dW d dK dY d5 d� dZ d d� d[ d\ d� d] d^ dx d< d_ dH dG dF d da d3 d� d db d dc dd d� da de dq dg dh d� di d d3 d
d d8 dl d d� dm dn d� do d d� dq dr d ds dt dh dj dv d� dx dy d dC dv dC d{ d3 d d| d} d� dV d| d� d7 d� d
 d7 d� d� d� d� d� dj d� d� dU d� dv dh d? dy d+ dO d� d� d d� dr d d} d� d� d� d� d� d' d d d� ds di d� d' dh d� d� dF d d* d) d� d� d� d6 d� d� d� d� d" d� d d@ d; d� d d� d- dV dV d� d� dI dL d� d� d- d� d� d d� d d d d� dx d� d! d dA d� d d� dM d� dG d� d d d d d dn d d� d� d  dy d d d# d� d$ d% d5 d
 d& d' d d( dA d) d* d� d+ d, d- d d& dN d/ d d d1 d2 d d4 d5 dq d7 d
d d d4 d9 d: d; dp d< d= d� d d> d� d@ dA d& dC dD d d dE d� dG dA dv dI dJ dK dL dM dw dO dP d� dR d7 d1 dS dL d� d! dU d dW d dM dY d5 d� dZ d dB d[ d\ d� d] d^ d1 d< d_ d` dG dF d� da d3 d� d db d dc dd d da de d� dg dh d di d d� d
d dZ dl d dI dm dn d[ do d d dq dr d ds dt d� dj dv d� dx dy d� dC dv d� d{ d3 d, d| d} d} dV d| di d7 d� d d7 d� d� d� d� d� dj d� d� dU d� d� dh d? d$ d+ dO d� d� d d� dr d d� d� d� d� d� d� d= d d d� ds di d� d' dh d� d� dF d� d* d) d$ d� d� d{ d� d� d� d� d" d� d d@ d@ d� d d+ d- dV d d� d� dZ dL d� da d- d� d� d d� dw d d d dx d� d� d dA d d d� d� d� dG d� d d d4 d d d d d� d1 d  dy dZ d d# d� d$ d% d� d
 d& d� d d( d� d) d* d� d+ d, d� d d& d( d/ d dX d1 d2 d� d4 d5 dl d7 d
d- d d4 d� d: d; de d< d= d� d d> d� d@ dA d� dC dD dO d dE d dG dA dt dI dJ d� dL dM ds dO dP d dR d7 di dS dL d d! dU d� dW d d� dY d5 d� dZ d d� d[ d\ d� d] d^ d� d< d_ d� dG dF dA da d3 d% d db d_ dc dd d� da de d$ dg dh dW di d d d
d d dl d d_ dm dn d  do d d dq dr d� ds dt d+ dj dv d` dx dy d� dC dv d� d{ d3 d� d| d} d� dV d| d� d7 d� d� d7 d� d d� d� d� dj d� d dU d� d� dh d? d� d+ dO d6 d� d d� dr d dx d� d� d
d� d� d� d d dF ds di di d' dh dr d� dF d d* d) d= d� d� d� d� d� d� d� d" d� d d@ dc d� d d� d- dV d� d� d� d dL d� d0 d- d� d� d d� d) d d dR dx d� d$ d dA d@ d d� dT d� dG dA d d d� d d dC d d� d d  dy d� d d# d+ d$ d% d� d
 d& dh d d( d d) d* d  d+ d, d� d d& d] d/ d d� d1 d2 d� d4 d5 d d7 d
df d d4 d� d: d; d^ d< d= d d d> d� d@ dA d~ dC dD d� d dE df dG dA d� dI dJ d dL dM dz dO dP d2 dR d7 d� dS dL d� d! dU d� dW d d� dY d5 d� dZ d d d[ d\ d� d] d^ d� d< d_ dK dG dF d� da d3 d| d db d dc dd dV da de d� dg dh d� di d d/ d
d d
 dl d d� dm dn d� do d d� dq dr d� ds dt d� dj dv d� dx dy d* dC dv d8 d{ d3 dj d| d} d� dV d| d d7 d� d
 d7 d� d d� d� de dj d� d� dU d� d� dh d? d� d+ dO d� d� d d� dr d d� d� d� d� d� d� d6 d d d� ds di d� d' dh d! d� dF d d* d) d� d� d� d6 d� d� d1 d� d" dr d d@ d0 d� d d d- dV dB d� d� dI dL d� dR d- d� dV d d� d d d d' dx d� dK d dA d� d d� dN d� dG d
d d d� d d d+ d d� ds d  dy d} d d# d� d$ d% d& d
 d& dd d( d( d) d* d� d+ d, d. d d& d. d/ d d d1 d2 d� d4 d5 dP d7 d
d d d4 dL d: d; d� d< d= d� d d> d d@ dA dj dC dD d) d dE dy dG dA d� dI dJ df dL dM dN dO dP d dR d7 d	 dS dL d� d! dU d9 dW d dC dY d5 dH dZ d d� d[ d\ d� d] d^ d d< d_ d� dG dF d� da d3 d d db d� dc dd d� da de dF dg dh dL di d d� d
d dk dl d d� dm dn d do d d� dq dr d� ds dt d� dj dv d� dx dy d� dC dv d d{ d3 d� d| d} d� dV d| d} d7 d� d� d7 d� d� d� d� d� dj d� d dU d� d� dh d? d$ d+ dO d� d� d dM dr d dO d� d� d6 d� d� d: d d d� ds di d] d' dh d� d� dF d� d* d) d� d� d� d d� d� d� d� d" dl d d@ d� d� d d+ d- dV d� d� d� d. dL d� d� d- d� d d d� d� d d d& dx d� d� d dA d] d d� d� d� dG d� d d dO d d d| d d� d� d  dy dM d d# d� d$ d% d d
 d& dE d d( dk d) d* d� d+ d, d� d d& d� d/ d d� d1 d2 d� d4 d5 d d7 d
d� d d4 d� d: d; ds d< d= d� d d> d� d@ dA d� dC dD d4 d dE d dG dA dq dI dJ dv dL dM d� dO dP d= dR d7 d� dS dL d d! dU ddW d dr dY d5 d� dZ d do d[ d\ d� d] d^ d	 d< d_ d: dG dF d� da d3 d� d db d dc dd d� da de d� dg dh d� di d dl d
d d� dl d d� dm dn d? do d d# dq dr d� ds dt d� dj dv d� dx dy d dC dv d� d{ d3 dQ d| d} d� dV d| d� d7 d� d/ d7 d� d4 d� d� d� dj d� d� dU d� d� dh d? dL d+ dO du d� d d� dr d dx d� d� d d� d� d� d d d ds di dg d' dh dr d� dF d� d* d) d� d� d� d- d� d� d� d� d" d� d d@ dc d� d d� d- dV dN d� d� d� dL d� d d- d� d� d d� d[ d d d� dx d� dQ d dA d� d d� d� d� dG d� d d dv d d dC d d� d� d  dy d� d d# d+ d$ d% dP d
 d& d� d d( d d) d* de d+ d, d� d d& d� d/ d d� d1 d2 d' d4 d5 d? d7 d
d d d4 d� d: d; d^ d< d= d: d d> d� d@ dA d= dC dD d� d dE df dG dA d� dI dJ d dL dM dz dO dP d� dR d7 d� dS dL d d! dU d; dW d d� dY d5 df dZ d d� d[ d\ d� d] d^ dm d< d_ d dG dF d� da d3 d\ d db d= dc dd dV da de d0 dg dh d� di d d d
d d8 dl d d� dm dn d� do d d� dq dr d� ds dt d� dj dv d[ dx dy dK dC dv d d{ d3 dj d| d} d� dV d| d d7 d� d� d7 d� d� d� d� d� dj d� d dU d� dv dh d? d� d+ dO da d� d d� dr d d� d� d� d� d� d� dx d d d  ds di d� d' dh d� d� dF d� d* d) d� d� d� d6 d� d� d� d� d" d� d d@ d| d� d d, d- dV d� d� d� d\ dL d� d3 d- d� d� d d� d� d d d� dx d� d7 d dA dq d d� d d� dG d� d d d� d d d� d d� dN d  dy d d d# d� d$ d% d� d
 d& d� d d( d d) d* d d+ d, d7 d d& d� d/ d d0 d1 d2 da d4 d5 dR d7 d
d8 d d4 d/ d: d; d� d< d= d� d d> d� d@ dA d� dC dD d) d dE dV dG dA d� dI dJ d� dL dM d0 dO dP d& dR d7 d� dS dL d� d! dU d dW d d dY d5 d� dZ d d� d[ d\ d� d] d^ d_ d< d_ d� dG dF d da d3 d� d db dr dc dd d da de d. dg dh d� di d d2 d
d de dl d d� dm dn d[ do d d dq dr d� ds dt d� dj dv d� dx dy d� dC dv do d{ d3 d� d| d} d- dV d| d� d7 d� d d7 d� d� d� d� d� dj d� d� dU d� d� dh d? d$ d+ dO d� d� d d7 dr d dO d� d� d% d� d� dd d d� ds di d� d' dh d d� dF dm d* d) d� d� d� d� d� d� d� d� d" df d d@ d� d� d d+ d- dV d d� d� d� dL d� da d- d� d3 d d� dt d d d dx d� dj d dA d� d d� dh d� dG d� d d d' d d d$ d d� dJ d  dy d d d# d; d$ d% d� d
 d& d� d d( d= d) d* d d+ d, d� d d& d� d/ d d� d1 d2 d� d4 d5 d2 d7 d
dr d d4 d� d: d; d� d< d= d� d d> d� d@ dA d� dC dD d� d dE d� dG dA d� dI dJ d dL dM d� dO dP d! dR d7 d� dS dL d� d! dU d� dW d d� dY d5 d� dZ d d� d[ d\ d� d] d^ d� d< d_ d� dG dF d da d3 d� d db d< dc dd dh da de dV dg dh d� di d d7 d
d d! dl d d< dm dn d� do d d� dq dr d\ ds dt do dj dv d� dx dy d� dC dv d d{ d3 dg d| d} d, dV d| d� d7 d� d� d7 d� d� d� d� dn dj d� dB dU d� d� dh d? d d+ dO d� d� d dX dr d d~ d� d� d� d� d� d� d d d3 ds di dZ d' dh dr d� dF d� d* d) d d� d� d" d� d� dT d� d" d7 d d@ dL d� d d+ d- dV d� d� d� d� dL d� d� d- d� d3 d d� d� d d d� dx d� d\ d dA d_ d d� d� d� dG d� d d d d d d d d� d d  dy d( d d# d+ d$ d% d� d
 d& d� d d( dT d) d* d� d+ d, di d d& d� d/ d d  d1 d2 dh d4 d5 dT d7 d
d( d d4 d� d: d; dw d< d= dq d d> dP d@ dA d� dC dD d@ d dE d� dG dA d� dI dJ d� dL dM dc dO dP d� dR d7 d dS dL dg d! dU d dW d d� dY d5 d� dZ d d d[ d\ d� d] d^ d d< d_ d� dG dF d� da d3 d_ d db dx dc dd dV da de dq dg dh d� di d d� d
d d� dl d d� dm dn d� do d dg dq dr d� ds dt d� dj dv d� dx dy d� dC dv d d{ d3 d� d| d} d� dV d| d� d7 d� d� d7 d� d� d� d� d� dj d� d� dU d� d dh d? d d+ dO dH d� d d� dr d d{ d� d� d� d� d� dU d d d ds di d# d' dh d� d� dF d� d* d) dH d� d� d� d� d� d� d� d" d d d@ dc d� d d� d- dV dl d� d� dI dL d� d3 d- d� d� d d� d d d d� dx d� d� d dA d� d d� d
 d� dG d� d d d d d dF d d� d� d  dy d� d d# d� d$ d% d d
 d& d' d d( d d) d* d� d+ d, d� d d& dN d/ d dB d1 d2 d� d4 d5 d d7 d
d� d d4 d� d: d; d� d< d= d� d d> d d@ dA d dC dD d� d dE d dG dA d^ dI dJ dE dL dM d� dO dP d� dR d7 dS dS dL d� d! dU d� dW d dt dY d5 d� dZ d dP d[ d\ d� d] d^ d� d< d_ dx dG dF d da d3 d� d db d� dc dd d� da de d� dg dh d� di d d d
d dY dl d d� dm dn d� do d d� dq dr d ds dt dS dj dv d� dx dy d dC dv d� d{ d3 d� d| d} d� dV d| d� d7 d� d= d7 d� d% d� d� d  dj d� d� dU d� d� dh d? d� d+ dO d� d� d d� dr d dP d� d� d@ d� d� d� d d d� ds di d d' dh dm d� dF d� d* d) d� d� d� d d� d� d� d� d" d d d@ d� d� d d� d- dV d� d� d� d� dL d� d� d� d� d� d d� dR d d ds dx d� d� d dA d� d d� d& d� dG d" d d d" d d d� d d� d� d  dy d� d d# d� d$ d% d d
 d& d d d( d� d) d* d� d+ d, dh d d& d� d/ d d� d1 d2 d' d4 d5 d d7 d
d� d d4 d� d: d; d d< d= d� d d> d� d@ dA d� dC dD d7 d dE d� dG dA d� dI dJ dP dL dM d� dO dP d_ dR d7 d� dS dL d* d! dU d� dW d d� dY d5 d dZ d d� d[ d\ d� d] d^ dT d< d_ dL dG dF d� da d3 d$ d db dl dc dd d� da de d
dg dh d� di d d� d
d d dl d d� dm dn d� do d d� dq dr d� ds dt d dj dv d� dx dy d� dC dv d� d{ d3 d3 d| d} dz dV d| dX d7 d� d� d7 d� d d� d� dR dj d� d> dU d� d/ dh d? d� d+ dO d d� d da dr d d� d� d� d d� d� d: d d d% ds di d� d' dh d6 d� dF d� d* d) d d� d� d� d� d� dO d� d" d d d@ de d� d d� d- dV d� d� d� d� dL d� d� d- d� du d d� d d d dF dx d� d� d dA d� d d� d' d� dG d� d d d d d d d d� d� d  dy d% d d# d d$ d% dP d
 d& dz d d( dR d) d* dO d+ d, d� d d& d� d/ d d� d1 d2 d� d4 d5 d d7 d
d� d d4 d� d: d; d� d< d= d� d d> d� d@ dA d
 dC dD d& d dE d- dG dA d� dI dJ d� dL dM d9 dO dP d5 dR d7 d� dS dL d� d! dU do dW d d� dY d5 d? dZ d dW d[ d\ d� d] d^ da d< d_ d� dG dF d� da d3 d� d db dP dc dd d8 da de dx dg dh d� di d d� d d dK dl d dQ dm dn d� do d d� dq dr d� ds dt d� dj dv d� dx dy d� dC dv d� d{ d3 dj d| d} d� dV d| d� d7 d� d� d7 d� d� d� d� dL dj d� d< dU d� dz dh d? d� d+ dO d� d� d d� dr d d� d� d� d� d� d� d d d d� ds di dI d' dh d� d� dF d� d* d) d� d� d� d6 d� d� d� d� d" d� d d@ d� d� d d� d- dV d� d� d� d7 dL d� d� d- d� d� d d� d� d d d dx d� d) d dA d d d� d^ d� dG d d d d� d d d d d� d: d  dy d d d# d� d$ d% d� d
 d& d0 d d( d� d) d* dA d+ d, d� d d& d d/ d dD d1 d2 dr d4 d5 d� d7 d
dR d d4 dU d: d; d� d< d= d� d d> d d@ dA d� dC dD dR d dE d dG dA d% dI dJ dr dL dM d6 dO dP d] dR d7 d� dS dL d3 d! dU d� dW d d� dY d5 d� dZ d dB d[ d\ d> d] d^ d d< d_ d_ dG dF d/ da d3 d d db d� dc dd d� da de d� dg dh d� di d d d
d d? dl d d� dm dn dJ do d dq dq dr d� ds dt d� dj dv d� dx dy d� dC dv dE d{ d3 d) d| d} d dV d| dQ d7 d� d d7 d� d
 d� d� d dj d� d� dU d� d� dh d? d$ d+ dO d� d� d dS dr d d� d� d� d% d� d� d d d d� ds di d] d' dh d� d� dF d^ d* d) ds d� d� dY d� d� d� d� d" d� d d@ de d� d d d- dV d[ d� d� d� dL d� d� d- d� dM d d� d� d d da dx d� d� d dA d� d d� d� d� dG d� d d d� d d d� d d� d� d  dy d� d d# dZ d$ d% d� d
 d& d� d d( dT d) d* d� d+ d, d� d d& d� d/ d d� d1 d2 d- d4 d5 dg d7 d
d� d d4 d` d: d; d� d< d= d� d d> d� d@ dA dG dC dD d� d dE d� dG dA d� dI dJ d% dL dM d& dO dP d� dR d7 d� dS dL d d! dU d� dW d d� dY d5 d0 dZ d d0 d[ d\ d` d] d^ d� d< d_ dL dG dF d da d3 d� d db d� dc dd d@ da de d� dg dh ds di d dw d
d d3 dl d dH dm dn d� do d dv dq dr dV ds dt d� dj dv d� dx dy d( dC dv d3 d{ d3 dr d| d} d� dV d| di d7 d� d� d7 d� dd� d� d� dj d� dM dU d� d` dh d? d� d+ dO d� d� d d� dr d d~ d� d� d� d� d� d� d d d� ds di d d' dh d2 d� dF d� d* d) dc d� d� d> d� d� d� d� d" dP d d@ d� d� d d� d- dV d� d� d� d� dL d� d� d- d� d� d d� dG d d d� dx d� d� d dA d7 d d� dh d� dG d= d d d� d d d� d d� d� d  dy dr d d# dL d$ d% dS d
 d& d� d d( d� d) d* di d+ d, d# d d& d� d/ d d� d1 d2 d d4 d5 d� d7 d
d! d d4 d d: d; ds d< d= d� d d> d	 d@ dA d� dC dD d d dE d� dG dA d� dI dJ d^ dL dM dS dO dP d5 dR d7 d� dS dL d� d! dU do dW d d� dY d5 d� dZ d d d[ d\ dy d] d^ dC d< d_ d� dG dF d� da d3 d� d db d� dc dd dV da de d� dg dh d( di d d d
d d7 dl d d, dm dn d� do d d� dq dr d� ds dt d� dj dv d> dx dy d� dC dv dw d{ d3 d� d| d} d! dV d| dZ d7 d� d� d7 d� d� d� d� dZ dj d� d dU d� d dh d? d� d+ dO d� d� d d� dr d d d� d� d� d� d� dx d d dU ds di d� d' dh d� d� dF d� d* d) d� d� d� dm d� d� d� d� d" d� d d@ d� d� d d� d- dV d� d� d� d� dL d� d[ d- d� d d d� dU d d d� dx d� d� d dA d� d d� d] d� dG d� d d d d d d� d d� d� d  dy dd d# d� d$ d% d� d
 d& d{ d d( d� d) d* dA d+ d, d& d d& d� d/ d d� d1 d2 dt d4 d5 dq d7 d
d� d d4 d d: d; dd< d= d@ d d> d� d@ dA ddC dD d~ d dE dU dG dA d
dI dJ d� dL dM d. dO dP d� dR d7 d3 dS dL d� d! dU d� dW d dM dY d5 d� dZ d dz d[ d\ d� d] d^ d� d< d_ d* dG dF d2 da d3 d d db d dc dd d da de d� dg dh d| di d d d
d d� dl d d� dm dn dJ do d d� dq dr dE ds dt d� dj dv dN dx dy d) dC dv dE d{ d3 dY d| d} d� dV d| dd d7 d� d� d7 d� d� d� d� d� dj d� d� dU d� d� dh d? d� d+ dO dO d� d do dr d d� d� d� dw d� d� d' d d d- ds di d� d' dh d� d� dF de d* d) d� d� d� d� d� d� d� d� d" d� d d@ d d d d� d- dV d< d� d� d� dL d� d d- d� d d d� du d d d dx d� d d dA d� d d� do d� dG dW d d d� d d db d d� d� d  dy d d d# d� d$ d% d� d
 d& d� d d( d= d) d* d� d+ d, dh d d& d� d/ d d� d1 d2 dZ d4 d5 dq d7 d
dV d d4 d& d: d; d� d< d= d0 d d> d d@ dA dy dC dD d* d dE d� dG dA dF dI dJ d dL dM d� dO dP d� dR d7 do dS dL d� d! dU dx dW d d� dY d5 d� dZ d d d[ d\ dC d] d^ dB d< d_ dg dG dF d da d3 d� d db d� dc dd d� da de d� dg dh d� di d dg d
d d= dl d dg dm dn d3 do d d� dq dr d� ds dt d0 dj dv d- dx dy dz dC dv dZ d{ d3 dl d| d} dr dV d| d� d7 d� d� d7 d� dc d� d� d dj d� d dU d� d[ dh d? dd d+ dO d d� d da dr d d� d� d� d� d� d� d� d d d� ds di d� d' dh d� d� dF dd* d) d$ d� d� d d� d� d7 d� d" d� d d@ d2 d d d� d- dV d- d� d� d� dL d� d0 d- d� d� d d� dG d d d� dx d� d� d dA dO d d� dT d� dG d� d d d� d d dX d d� d d  dy d� d d# d� d$ d% d d
 d& d� d d( d_ d) d* d d+ d, d d d& d� d/ d d� d1 d2 d� d4 d5 d d7 d
d d d4 d� d: d; dd< d= d: d d> d� d@ dA d� dC dD d� d dE da dG dA dA dI dJ d dL dM d� dO dP d% dR d7 d] dS dL d1 d! dU dh dW d d� dY d5 d� dZ d d d[ d\ d� d] d^ d d< d_ d� dG dF d� da d3 d_ d db d dc dd d da de dq dg dh d� di d d/ d
d d� dl d d� dm dn d� do d d" d� dr dj ds dt d� dj dv dy dx dy d dC dv d� d{ d3 d� d| d} d� dV d| d� d7 d� d� d7 d� d� d� d� d� dj d� dr dU d� d� dh d? d
 d+ dO d� d� d d� dr d d� d� d� d� d� d� dL d d d� ds di d d' dh d� d� dF d� d* d) d" d� d� d� d� d� d� d� d" d d d@ d� d� d dt d- dV d d� d� d� dL d� d d- d� d d d� d d d d� dx d� d� d dA d> d d� d� d� dG d� d d d� d d dq d d� dj d  dy d� d d# d! d$ d% d� d
 d& d0 d d( d� d) d* d� d+ d, d� d d& d} d/ d d| d1 d2 d� d4 d5 d� d7 d
d d d4 d� d: d; d� d< d= da d d> dm d@ dA dR dC dD d d dE dJ dG dA d dI dJ d� dL dM d- dO dP d dR d7 d� dS dL d+ d! dU dV dW d d dY d5 d* dZ d d� d[ d\ d d] d^ d� d< d_ d
dG dF d� da d3 d� d db d� dc dd d� da de d� dg dh dC di d dU d
d d# dl d d� dm dn dW do d d� dq dr d� ds dt d� dj dv d dx dy dN dC dv dE d{ d3 d� d| d} de dV d| d� d7 d� d d7 d� d� d� d� d� dj d� ddU d� d� dh d? d� d+ dO d� d� d d' dr d d� d8 d� d� d� d� d� d d d� ds di d� d' dh dH d� dF d� d* d) d� d� d� d d� d� d� d� d" d~ d d@ d� d� d d+ d- dV dO d� d� d� dL d� d� d- d� d d d� du d d d dx d� dh d dA dy d d� d� d� dG d� d d dy d d dH d d� dg d  dy d d d# d� d$ d% d d
 d& d� d d( d] d) d* d� d+ d, dh d d& d� d/ d d d1 d2 d d4 d5 d6 d7 d
d� d d4 d� d: d; d( d< d= d� d d> d� d@ dA d� dC dD d� d dE d dG dA d� dI dJ dv dL dM d� dO dP d� dR d7 d� dS dL d d! dU d� dW d d� dY d5 d� dZ d d? d[ d\ d\ d] d^ d� d< d_ d� dG dF d da d3 d� d db d� dc dd d� da de d� dg dh d di d d� d
d dx dl d d� dm dn d� do d d: dq dr d ds dt d dj dv d dx dy d dC dv dV d{ d3 d� d| d} dv dV d| d5 d7 d� d� d7 d� d d� d� d� dj d� d@ dU d� d� dh d? d d+ dO d6 d� d d� dr d d d� d� d� d� d� d� d d d� ds di d� d' dh d� d� dF d� d* d) d d� d� dV d� d� d� d� d" d� d d@ d| d� d d� d- dV d� d� d� d dL d� d d- d� d� d d� dG d d d� dx d� d� d dA d� d d� dx d� dG d� d d d� d d dC d d� dY d  dy d< d d# d+ d$ d% d� d
 d& d� d d( d� d) d* d� d+ d, d� d d& d� d/ d d� d1 d2 d� d4 d5 d+ d7 d
d d d4 d~ d: d; d^ d< d= d� d d> d� d@ dA d� dC dD d� d dE d dG dA d, dI dJ dd dL dM d� dO dP d� dR d7 d� dS dL d� d! dU d� dW d d� dY d5 d� dZ d d� d[ d\ d� d] d^ d� d< d_ d� dG dF d� da d3 d� d db d dc dd d� da de dq dg dh d� di d d/ d
d d� dl d dB dm dn dI do d dm dq dr dY ds dt d� dj dv d dx dy d� dC dv d� d{ d3 dj d| d} d� dV d| dW d7 d� d� d7 d� d� d� d� dG d� d� d� dU d� d� dh d? dd+ dO d� d� d d� dr d d d� d� d1 d� d� dg d d d8 ds di d� d' dh d� d� dF d d* d) d+ d� d� d6 d� d� dS d� d" d� d d@ d9 d� d d� d- dV d� d� d� d) dL d� d� d- d� do d d� d d d de dx d� d7 d dA dt d d� d* d� dG d� d d dr d d d� d d� dV d  dy d d d# d� d$ d% d
d
 d& dk d d( dT d) d* d� d+ d, dD d d& d	 d/ d df d1 d2 d d4 d5 d d7 d
d8 d d4 d9 d: d; d2 d< d= d_ d d> dK d@ dA d! dC dD d� d dE d� dG dA d[ dI dJ d� dL dM dN dO dP dQ dR d7 d dS dL d� d! dU dV dW d d dY d5 d* dZ d d	 d[ d\ d d] d^ d� d< d_ d* dG dF df da d3 d� d db d� dc dd d/ da de d� dg dh dJ di d d2 d
d d# dl d d� dm dn d[ do d d� dq dr d+ ds dt d� dj dv d< dx dy d� dC dv d� d{ d3 d� d| d} dR dV d| dd d7 d� d� d7 d� d{ d� d� d� dj d� d� dU d� d� dh d? d- d+ dO dP d� d d� dr d dO d� d� d� d� d� d� d d d4 ds di dJ d' dh dH d� dF d� d* d) d� d� d� d� d� d� d� d� d" dP d d@ d� d� d d+ d- dV dv d� d� d� dL d� da d- d� d d d� du d d d  dx d� d d dA d� d d� d  d� dG d� d d d� d d dX d d� d d  dy d� d d# d; d$ d% d d
 d& d d d( d= d) d* d� d+ d, dr d d& d  d/ d d d1 d2 d� d4 d5 d d7 d
d� d d4 d� d: d; d� d< d= d8 d d> d� d@ dA d� dC dD d� d dE d dG dA d> dI dJ d dL dM d� dO dP d! dR d7 d� dS dL d  d! dU dx dW d d dY d5 d� dZ d d� d[ d\ d� d] d^ d� d< d_ d dG dF dQ da d3 d
 d db d� dc dd d� da de d� dg dh d� di d d� d
d d dl d d� dm dn d do d d dq dr d� ds dt dO dj dv dx dx dy d� dC dv d# d{ d3 d� d| d} dl dV d| d� d7 d� d d7 d� d� d� d� d9 dj d� d? dU d� d� dh d? d� d+ dO d� d� d d� dr d dP d� d� d� d� d� d3 d d da ds di dg d' dh d� d� dF d� d* d) d� d� d� d[ d� d� d8 d� d" du d d@ dU d� d d� d- dV d d� d� d� dL d� dB d- d� d\ d d� d� d d dR dx d� d' d dA de d d� d� d� dG d d d d| d d d� d d� d� d  dy d� d d# dQ d$ d% d� d
 d& d6 d d( d� d) d* d� d+ d, d� d d& dS d/ d d� d1 d2 dp d4 d5 d� d7 d
dp d d4 d� d: d; dK d< d= dL d d> dv d@ dA dY dC dD dn d dE d� dG dA d� dI dJ d� dL dM dn dO dP d� dR d7 d� dS dL d" d! dU d� dW d d# dY d5 d� dZ d d d[ d\ d� d] d^ d� d< d_ d� dG dF d da d3 d  d db d= dc dd d� da de d0 dg dh d� di d d� d
d d  dl d d� dm dn ddo d d� dq dr dds dt d� dj dv di dx dy d� dC dv d� d{ d3 d d| d} d dV d| d� d7 d� d� d7 d� d0 d� d� d� dj d� d dU d� dD dh d? da d+ dO d d� d d dr d d� d� d� d� d� d� d� d d dt ds di d; d' dh d� d� dF d� d* d) d� d� d� de d� d� d d� d" dA d d@ d0 d� d d% d- dV dV d� d� d+ d� d� d� d- d� d� d d� dM d d d� dx d� d# d dA dT d d� d� d� dG db d d d� d d d� d d� d� d  dy d� d d# d d$ d% d� d
 d& d� d d( d� d) d* d� d+ d, dk d d& d� d/ d d� d1 d2 d d4 d5 d d7 d
d� d d4 d� d: d; d� d< d= d� d d> dN d@ dA d� dC dD d� d dE dr dG dA d! dI dJ d9 dL dM d� dO dP d� dR d7 d� dS dL d� d! dU d dW d dn dY d5 d} dZ d d d[ d\ d d] d^ d} d< d_ dc dG dF d� da d3 d� d db d dc dd d da de d� dg dh d di d d2 d
d d" dl d dI dm dn d� do d d� dq dr d� ds dt db dj dv d� dx dy d� dC dv d� d{ d3 d d| d} d' dV d| d� d7 d� d� d7 d� d� d� d� d� dj d� d� dU d� dA dh d? d$ d+ dO d� d� d d� dr d d� d� d� d% d� d� d d d d� ds di d d' dh dN d� dF d2 d* d) d� d� d� d� d� d� d� d� d" dP d d@ d� d� d d� d- dV d� d� d� du dL d� da d- d� d d d� d� d d dQ dx d� d� d dA dm d d� d� d� dG d� d d d� d d d� d d� d� d  dy d d d# d� d$ d% d� d
 d& d d d( d= d) d* d� d+ d, d� d d& db d/ d d� d1 d2 d� d4 d5 d6 d7 d
d� d d4 dF d: d; d d< d= d� d d> d� d@ dA d# dC dD d� d dE d� dG dA dy dI dJ d� dL dM d� dO dP d� dR d7 d� dS dL d, d! dU dK dW d dY dY d5 d� dZ d d d[ d\ d d] d^ d� d< d_ d� dG dF d da d3 d� d db d� dc dd dc da de d dg dh d� di d dQ d
d dY dl d d� dm dn d do d d� dq dr d� ds dt d� dj dv d� dx dy d dC dv dB d{ d3 d� d| d} d� dV d| dX d7 d� d9 d7 d� d� d� d� ddj d� d� dU d� d@ dh d? d� d+ dO d� d� d d� dr d d~ d� d� d� d� d� d d d dd ds di d� d' dh dr d� dF d� d* d) d- d� d� d� d� d� d� d� d" d� d d@ dc d� d dR d- dV d d� d� d dL d� d d- d� d� d d� d_ d d d} dx d� d� d dA d@ d d� dT d� dG d� d d d� d d dC d d� d� d  dy d( d d# d� d$ d% d� d
 d& d� d d( d d) d* do d+ d, dG d d& d� d/ d d� d1 d2 d� d4 d5 d d7 d
d� d d4 dv d: d; d^ d< d= d: d d> d� d@ dA d� dC dD d� d dE d dG dA dA dI dJ d dL dM d� dO dP dp dR d7 d� dS dL d d! dU d dW d d� dY d5 d dZ d d� d[ d\ d� d] d^ d d< d_ dH dG dF dA da d3 d� d db d� dc dd dV da de d� dg dh d� di d d/ d
d d8 dl d d� dm dn d� do d dh dq dr di ds dt d� dj dv d� dx dy d
dC dv d7 d{ d3 d� d| d} d| d� d| d d7 d� d� d7 d� d[ d� d� d� dj d� d� dU d� dv dh d? d
 d+ dO d� d� d d. dr d d� d� d� d� d� d� dx d d d8 ds di dq d' dh dq d� dF d� d* d) d� d� d� dI d� d� d� d� d" d= d d@ d� d� d d� d- dV d� d� d� dI dL d� d3 d- d� d� d d� d� d d dy dx d� d7 d dA d� d d� d] d� dG dI d d dG d d dF d d� dV d  dy d d d# d d$ d% dA d
 d& d' d d( d( d) d* d d+ d, d� d d& d� d/ d d0 d1 d2 d3 d4 d5 dP d7 d
d� d d4 d$ d: d; d2 d< d= d� d d> d? d@ dA d- dC dD dk d dE dO dG dA d� dI dJ d� dL dM d� dO dP dM dR d7 d� dS dL dq d! dU dV dW d d� dY d5 d� dZ d dB d[ d\ d> d] d^ d d< d_ d� dG dF d� da d3 d d db d dc dd d da de d� dg dh d� di d d2 d
d d" dl d dI dm dn d� do d d� dq dr d� ds dt d� dj dv d� dx dy d� dC dv dN d{ d3 d� d| d} d dV d| dd d7 d� dC d7 d� d% d� d� d� dj d� d� dU d� d7 dh d? d] d+ dO d d� d dm dr d dO d� d� d� d� d� dN d d dF ds di d� d' dh dH d� dF d� d* d) d� d� d� d% d� d� d~ d� d" dz d d@ d� d� d dS d- dV d� d� d� d. dL d� d� d- d� d� d d� d� d d d dx d� d) d dA dA d d� d� d� dG d� d d d� d d d� d d� d� d  dy d� d d# d8 d$ d% d d
 d& d d d( d= d) d* d� d+ d, d} d d& d4 d/ d dM d1 d2 d� d4 d5 dq d7 d
dD d d4 d� d: d; d� d< d= d  dW d> dz d@ dA d� dC dD d% d dE d� dG dA dF dI dJ dN dL dM d� dO dP d" dR d7 d� dS dL d� d! dU d| dW d d� dY d5 d� dZ d d d[ d\ d` d] d^ d� d< d_ d: dG dF dA da d3 d� d db d� dc dd d	 da de d� dg dh dG di d d� d
d d dl d d� dm dn d� do d d� dq dr d� ds dt d! d� dv d� dx dy d~ dC dv dI d{ d3 dE d| d} d� dV d| dX d7 d� d� d7 d� d� d� d� dR dj d� dB dU d� d� dh d? d d+ dO d� d� d ddr d d~ d� d� d� d� d� d� d d di ds di d� d' dh dr d� dF d� d* d) d d� d� dE d� d� d d� d" d� d d@ dc d� d d� d- dV d	 d� d� dn dL d� d d- d� d� d d� d- d d d� dx d� d� d dA dL d d� d& d� dG d� d d d� d d dC d d� d� d  dy d! d d# d� d$ d% d� d
 d& d� d d( d d) d* d� d+ d, d� d d& d� d/ d d� d1 d2 d� d4 d5 d+ d7 d
d� d d4 d d: d; d� d< d= d d d> dk d@ dA d� dC dD d" d dE d� dG dA dA dI dJ d dL dM d� dO dP d� dR d7 d dS dL d d! dU d dW d d� dY d5 d� dZ d d� d[ d\ d� d] d^ d d< d_ d� dG dF d� da d3 d_ d db d~ dc dd dV da de dq dg dh d� di d d� d
d d� dl d d8 dm dn d� do d d� dq dr d� ds dt d� dj dv d dx dy d� dC dv d8 d{ d3 dj d| d} d� dV d| d� d7 d� d� d7 d� d d� d� dY dj d� d� dU d� dz dh d? d� d+ dO d� d� d dg dr d dv d� d� d� d� d� dx d d d8 ds di dI d' dh d� d� dF d� d* d) d� d� d� d6 d� d� d� d� d" d d d@ d d� d df d- dV d d� d� d� dL d� d, d- d� d� d d� dx d d d dx d� d d dA d\ d d� d� d� dG d d d d! d d d d d� d� d  dy dr d d# d5 d$ d% d� d
 d& d� d d( d� d) d* d d+ d, d[ d d& d� d/ d d� d1 d2 d� d4 d5 d� d7 d
du d d4 dT d: d; ds d< d= d� d d> d# d@ dA da dC dD d� d dE d- dG dA d� dI dJ df dL dM d� dO dP d dR d7 d� dS dL d� d! dU d� dW d dI dY d5 d� dZ d d� d[ d\ d� d] d^ dX d< d_ d� dG dF d� da d3 d� d db d� dc dd d� da de df dg dh d� di d d� d
d d� dl d d dm dn dB do d d� dq dr dX ds dt d� dj dv dW dx dy dF dC dv db d{ d3 dO d| d} d� dV d| di d7 d� dJ d7 d� d5 d� d� d� dj d� d dU d� dA dh d? d( d+ dP dk di d d� dr d d� d8 dt d� d� d� d d d d ds d� dh d' dB d� d� d8 d� d* dz d� d� d� d� d� d� d� d� d" d� d d@ d� d� d dW d- dV d� d� d� d� dL d� d� d- d� d� d d� d� d d d� dx d� d� d dA d  d d� d� d� dG d� d d d� d d d� d d� dh d  dy d� d d# d� d$ d% d< d
 d& d d d( d� d) d* dH d+ d, d� d d& d d/ d d� d1 d2 d� d4 d5 d� d7 d
dv d d4 d� d: d; d� d< d= d� d d> d� d@ dA d� dC dD dm d dE d� dG dA d� dI dJ d7 dL dM d� dO dP d� dR d7 d dS dL d� d! dU dW dW d dn dY d5 d� dZ d d1 d[ d\ dx d] d^ dD d< d_ d� dG dF d� da d3 dx d db d� dc dd d� da de d� dg dh d# di d d� d
d d dl d d� dm dn d� do d d� dq dr dK ds dt d� dj dv d� dx dy dR dC dv d� d{ d3 d� d| d} d dV d| d	 d7 d� da d7 d� d� d� d� dU dj d� dH dU d� d dh d? d� d+ dO dS d� d du dr d d� d� d� d� d� d� d
 d d d\ ds di d, d' dh d d� dF d� d* d) d� d� d� d� d� d� dd d� d" d� d d@ df d� d d� d- dV d� d� d� d� dL d� d� d- d� d� d d� d� d d d� dx d� d� d dA d� d d� d� d� dG d� d d dM d d d� d d� dA d  dy d� d d# d8 d$ d% d| d
 d& dD d d( dG d) d* d d+ d, d� d d& d� d/ d d� d1 d2 d< d4 d5 d� d7 d
dy d d4 d" d: d; d� d< d= d� d d> d d@ dA d� dC dD d� d dE d� dG dA d dI dJ dB dL dM dn dO dP dB dR d7 dd dS dL d> d! dU d7 dW d dF dY d5 dM dZ d d d[ d\ d� d] d^ d3 d< d_ d� dG dF d da d3 d� d db d� dc dd d� da de d� dg dh d� di d d� d
d dL dl d d� dm dn d� do d d8 dq dr dy ds dt d� dj dv dP dx dy d) dC dv d� d{ d3 dH d| d} d dV d| d d7 d� dt d7 d� dD d� d� d� dj d� de dU d� da dh d? d d+ dO d` d� d d� dr d d� d� d� d7 d� d� d� d d d@ ds di d	 d' dh du d� dF d� d* d) dD d� d� d� d� d� d* d� d" dm d d@ dH d� d d� d- dV d� d� d� d dL d� d� d- d� d� d d� d d d d� dx d� d� d dA d
 d d� dk d� dG dr d d dz d d dE d d� d� d  dy d^ d d# d� d$ d% d� d
 d& dg d d( d� d) d* du d+ d, d d d& d� d/ d d� d1 d2 dh d4 d5 d d7 d
d� d d4 d d: d; d d< d= d� d d> d" d@ dA d� dC dD dN d dE d� dG dA d? dI dJ d� dL dM d( dO dP dV dR d7 d� dS dL d� d! dU d� dW d d� dY d5 dI dZ d d% d[ d\ d~ d] d^ dl d< d_ dK dG dF d� da d3 d� d db d
 d+ dd d da de d> dg dh dg di d dA d
d d~ dl d d< dm dn d7 do d d� dq dr d� ds dt d� dj dv d� dx dy d� dC dv d� d{ d3 d� d| d} d< dV d| d� d7 d� do d7 d� d� d� d� d� dj d� d dU d� d� dh d? d� d+ dO d� d� d dl dr d d% d� d� d� d� d� d d d d� ds di d d' dh d: d� dF d� d* d) d� d� dy d: d� d� d� d� d] dU d d� d� d� d, dW d- d� d� d� d� d+ dL d� d) d- ds d� d d� d� d d	 d� d� d� d� d� dy d� d� d d� d� d� dn d9 d d� d dL d d� d_ d� dn dA de d d, d: d� d� d# d� d? d d� d~ d d4 d� d� dq d� d� d� dz d^ d� d� d	 d� dH dS d8 d@ d� de d� d� dj d� d d dU d� d< d; df d d> dU d@ d� d� d� d� d" d dx d� d~ dy dM d{ d� d� d\ d� d= dc d, d� d� de d\ d� d[ dB d% dw d+ d` dm d� dY d d� d d  d# d� d do d� dd dQ d< d� d� dG d4 d� d} dY d d dK dD d� d^ dz da d) d� dg d" dw d� d� d8 d
dm d d� dO d� dm d� de do d5 d" d� d� dk ds dd+ d^ d3 d� dx dh d� dC d3 d� d8 d� d� d| d d� d� dS d� d7 d� dA d7 dk d d� d	 d( dj da d dc d� d� dh d� d� d+ d d� d. d d8 dr d� dN d� d� d� d� d� d� d d} d d� d� d� d' d" d� dc d4 d� d* de db d� d� d� d� dP di d� dh dl d� d d d� d d� d- d� d� d� d� dc dL d= d> d� d d d dr dZ d d	 d
 d� d* d
d dy d� d� d dB d� d- d� d d d d� d� d� d d_ d| d dA d" d d� d
 d$ d� d d� d d� d d~ d� d d� d� d+ d� d� d d? d^ d
d� d� d1 dH d d� d d� d7 d� d� d dF d dn d� d� d< d� d� d d� d6 d@ d" d
 dC d� d� d d) d� dG dy dd d� d� d� dL d^ d& dO d d� d� d� d\ dS d` d\ dk dw d dW d� d� dY d dK d* dN d5 d[ d� do d� dd dQ d< d� d� dG d4 d� d} d d d dK dD db d^ dz da d) dS dg d" dw d� d� d8 d
dm d d$ dO d� dm d� dM do d5 d" d� d� dk ds dd+ d d3 d� dx dh d� dC d3 d� d8 d� d� d| d d� d� dS d� d7 d� d d7 dk d d� d: d( dj da d d
d� d� dh d� dj d+ d d� d. d� d8 dr d� dN d� d� d� d� d� dB d d} d d� d d� d' d" d� dy d4 d� d* de d� d� d� d� d� d� di d� dh dl d� d d d� d d� d- d� d� d� d^ dc dL d= d> d� d d d dr d� d d	 d
 d� d� d
d dy d� d� d dB d� d- dX d d d d� d� d� d d_ d| d� dA d" d d� d� d$ d� d d� d, d� d d~ d� d d� d� d+ d� dM d d? d^ d
d� d� d1 dH d dH d d� d7 d� d" d dF d dn dO d� d< d� d� d� d� d6 d@ d" d� dC d� d� d ds d� dG dy dd d{ d� d� dL d^ dA dO d d� d� d� d\ dS d` d\ d` dw d dW d� dI dY d dK d* d� d5 d[ d� do d� dd dQ d< d� d� dG d4 d� d} db d d dK dD d d^ dz da d) dd dg d" dw d� d( d8 d
dm d dj dO d� dm d� dg do d5 d" d� d� dk ds dd+ d& d3 d� dx dh d� dC d3 d� d8 d* d� d| d d� d� dS d� d7 d� d� d7 dk d d� dJ d( dj da d d} d� d� dh d� d� d+ d d� d. d� d8 dr d� dN dZ d� d� d� d� d� d d} d d� d� d� d' d" d� d� d4 d� d* de d d� d� d� d� d� di d� dh dl d� d d d� d dR d- d� d� d� d� dc dL d= d> dW d d d dr d0 d d	 d
 d� d� d
d dy d� d� d dB d� d- d# d d d d� d� d� d d_ d| d� dA d" d d� d� d$ d� d d� d� d� d d~ d� d� d� d� d+ d� dZ d d? d^ d
d| d� d1 dH d d� d d� d7 d� dl d dF d dn d� d� d< d� d� dI d� d6 d@ d" d� dC d� d� d d( d� dG dy dd d� d� d� dL d^ d� dO d d� d� d: d\ dS d` d\ d dw d dW d� d9 dY d dK d* d� d5 d[ d� do d| dd dQ d< d� d4 dG d4 d� d} d� d d dK dD d@ d^ dz da d) dL dg d" dw d� dd d8 d
dm d dG dO d� dm d� d� do d5 d" d� d� dk ds dd+ d
 d3 d� dx dh d[ dC d3 d� d8 d� d� d| d d� d� dS d� d7 d� d^ d7 dk d d� d� d( dj da d d� d� d� dh d� d� d+ d d� d. d� d8 dr d� dN d d� d� d� d� d2 d d} d d� d� d� d' d" d� dQ d4 d� d* de d� d� d� d� d� d< di d� dh dl dk d d d� d d d- d� d� d� d� dc dL d= d> dj d d d dr d} d d	 d
 d� dg d
d dy d� d� d dB d� d- d� d d d d� d� d� d d_ d| d� dA d" d d� d^ d$ d� d d� d� d� d d~ d� d� d� d� d+ d� d� d d? d^ d
dc d� d1 dH d d� d d� d7 d� d� d dF d dn d< d� d< d� d� d� d� d6 d@ d" d� dC d� d� d d� d� dG dy dd dv d� d� dL d^ d� dO d d� d� d� d\ dS d` d\ d� dw d dW d� d dY d dK d* de d5 d[ d� do d� dd dQ d< d� d� dG d4 d� d} d� d d dK dD d� d^ dz da d) d
 dg d" dw d� d� d8 d
dm d d* dO d� dm d� d5 do d5 d" d� d� dk ds dd+ d� d3 d� dx dh d0 dC d3 d� d8 d� d� d| d d� d dS d� d7 d� d� d7 dk d d� d� d( dj da d d� d� d� dh d� dq d+ d d� d. d2 d8 dr d� dN d d� d� d� d� d� d d} d d� d� d� d' d" d� dF d4 d� d* de d� d� d� d� d� d� di d� dh dl d� d d d� d d� d- d� d� d� d dc dL d= d> d� d d d dr d� d d	 d
 d� d� d
d dy d� d� d dB d� d- d� d d d d� d� d� d d_ d| d� dA d" d d� d� d$ d� d d� d� d� d d~ d� d� d� d� d+ d� d d d? d^ d
d d� d1 dH d d� d d� d7 d� d� d dF d dn d� d� d< d� d� dG d� d6 d@ d" d\ dC d� d� d d� d� dG dy dd d� d� d� dL d^ d� dO d d� d� dd\ dS d` d\ d� dw d dW d� d dY d dK d* d d5 d[ d� do d� dd dQ d< d� d� dG d4 d� d� dH d d dK dO d0 d^ dz da d� d� d� d� dl d
 d� d� d dm d_ dl d d dT d� d� do da dg d� d� dk ds d� d� d� d3 d� dx d� d} d� d3 d� d{ d� d d� d d� dV d= d d� d� d\ d7 dk d d� d_ d� d� dT d� dU d� d� d7 dB d� d} d� d� d� d� d8 d� d� dJ d� d� d# d� d= dQ d d+ d1 ds d� d� d� d� dl dW d� d� d4 dI d0 d� d� d� d� d� d� d d" d� dv d� d
 d dP du d- d4 d� d� d� dc d0 d; d d- d d d� d dM d d} d
 d� d� d� d d� d d@ d dC d� dV d dO d d d d� d� d. d_ dk d  d� d" dM d, d d$ d< d d� d? d� d d� d� d d� d� d+ d5 d� d� d? dg d/ d  d� d dH d� d4 d, d� d� d� d
 d d� d d� d� d� d< d� d� dM d� d� d@ d� d} dB d� d� d d� d� d� dy d dI d� d� d� d� d\ dO da d� d' d� d= dS d; d0 di dw dH dW d� d^ d d d dZ d  d5 d� d� d� d] d� dQ d� d� dQ dG d� d� d dv dK d d d� d� d^ d� da dw dH d^ d" d� di d2 d8 d� dm d� dl d d� d� d� d� do d# d" d� d� d ds d� d! d� d3 dm dx d� dI dB d3 d� d{ dh d� d? d ds dV d& d� d� dT d� d7 d d d du d dj d d� de d� d� dh dS d� d� d d8 d� d- d8 d� d� d� d� dc d� d� d= d� d d	 d d� d� d d' d3 ddw d4 d d* d� d� d� d� d: d� d� di du dh d7 d dO d d dP d� d- dG d� dL d� d� dL d\ d� d� d dH d dK d dN d	 d� dx d{ d
d� dy d� d d� dB d{ d� da d d� d d� d� d� d d� d d dA d3 d d dO d� d� da d
 d| d� d� d~ d� d) dQ d� d� d# d� d d| d^ d� d d� d1 d dw d� d d� d7 d� d� d� dF d  d: dL d� d� d� d� d d� d6 d dy d	 dC d8 d� d  d� d� dG d� dM d� d� d� dL d� d= d d d� dR dX d\ d& d` d� d! d� d d� d� dg dY d, dK d d d# d[ d� d� d� dd d� d< d d� d� d4 d� da dh d d dK d� dc dg dz d d� d dg d3 dw d! d� d� d d� d� dQ d� d� dm d� d� d� d5 d� d� d� d� d� dd{ d� d( d� d d� d d� dw d� dz dt g��Z dZ d� d� f \ Z Z d- d d d d d d d	 d
 dx d� d
d dy d d d dB d� d� d d d d d d� d� d d_ d d  dA d" d d, dO d$ d� d d
 d? d� d d~ d� d) d� d� d+ d# d� d d? d^ d/ d d� d1 dH dw d4 d d� d7 d� d� d dF d d: d� d� d< d� d� d d� d6 d@ dy d} dC d� d� d d� d� dG dy dM dI d� d� dL d� d= dO d d� dR d� d\ dS d` d0 d! dw d dW d� d^ dY d dK dZ d d5 d[ d� d� d] dd dQ d< d� d� dG d4 d� da dv d d dK d� dc d^ dz da d� dH dg d" dw di d� d8 d
dm d_ dl dO d� dm d� d� do d5 d" dq d� dk ds dd! dj d3 d� dx dA dI dC d3 d� d{ dv d� d| d d� dV dS d� d7 dT d� d7 dk d d� du d( dj da d� dU d� d� dh d& d� d+ d d� d� d� d8 dr d� dJ d� d� d� d� d= dQ d d} d ds d� d� d' d" dd� d4 d� d* d� d� d� d� d� d� d� di d� dh d� d d d d� dP du d- d� d� d� d� dc dL d= d� g� Z xn e e e � k � r�~Pn  e e e � k � r�~d� Z n  e e e e e e A� 7Z e dV 7Z e dV 7Z � q�~We  j e � d Ud S(  i����Ni�   i\   i   i
  i�   i   i1   i�   i�   id   i�   i�   i�   i_   i�   i�   i�   iY   iS   i2   i�   i5   i=   i�   i�   i�   iT   i
   i   i�   i�   i!   iv   i�   iu   i    iK   i�   i�   i   ib   iH   i�   i�   i�   i�   iN   i�   i�   i�   i   i7   i?   i}   iL   i0   i�   i�   i�   i�   iy   i/   iQ   i{   i*   i�   i�   i9   ir   i�   i�   iO   i�   i~   iB   i�   i�   i�   i�   i�   it   i�   iW   i�   i   i   i�   i�   i   is   i'   ij   i�   i`   i&   iR   i   iI   i�   i   i�   i   i   i�   ii   iF   i�   iV   i�   iJ   i^   i-   i�   i.   i�   i   i�   i�   i�   i   i+   i%   i�   i;   i�   i�   i3   i   i"   i�   i�   il   i�   i6   i�   i�   i@   i�   ix   i�   iM   i�   i�   iA   i�   i)   i�   i|   i�   i   i4   i   im   iX   i�   i�   i�   i�   i�   iZ   i8   i�   i�   i�   i   i�   i�   i   ih   i#   i�   i�   i�   if   i(   i[   ic   iG   i�   iU   i�   i�   i$   i�   i   iE   ia   i�   i   i   i�   iz   i�   i�   i�   ik   i�   i�   i�   ie   i�   i<   i   i�   i   i   i�   ip   i�   io   iw   i�   i�   i,   i�   i�   i�   i   i�   i�   i�   i�   i�   i�   i�   i�   i�   i   iq   i�   i�   i�   i�   i�   i�   i   i�   i�   i    i�   iP   i�   i�   i>   ig   in   i   iD   i:   i]   i�   i�   iC   i�   i	   i�   t    (	   t   marshalt   dt   et   it   jt   kt   lent   chrt   loads(    (    (    s   <script>t   <module>   s  � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � � �   	
(   t   marshalt   loads(    (    (    s'   /home/x/Documents/firecrack/ngentot.pyet   <module>   s    
#!/usr/bin/env python
# StatsGen - Password Statistical Analysis tool
#
# This tool is part of PACK (Password Analysis and Cracking Kit)
#
# VERSION 0.0.3
#
# Copyright (C) 2013 Peter Kacherginsky
# All rights reserved.
#
# Please see the attached LICENSE file for additional licensing information.

import sys
import re, operator, string
from optparse import OptionParser, OptionGroup
import time

VERSION = "0.0.3"

class StatsGen:
    def __init__(self):
        self.output_file = None

        # Filters
        self.minlength   = None
        self.maxlength   = None
        self.simplemasks = None
        self.charsets    = None
        self.quiet = False
        self.debug = True

        # Stats dictionaries
        self.stats_length = dict()
        self.stats_simplemasks = dict()
        self.stats_advancedmasks = dict()
        self.stats_charactersets = dict()

        # Ignore stats with less than 1% coverage
        self.hiderare = False

        self.filter_counter = 0
        self.total_counter = 0

        # Minimum password complexity counters
        self.mindigit   = None
        self.minupper   = None
        self.minlower   = None
        self.minspecial = None

        self.maxdigit   = None
        self.maxupper   = None
        self.maxlower   = None
        self.maxspecial = None

    def analyze_password(self, password):

        # Password length
        pass_length = len(password)

        # Character-set and policy counters
        digit = 0
        lower = 0
        upper = 0
        special = 0

        simplemask = list()
        advancedmask_string = ""

        # Detect simple and advanced masks
        for letter in password:
 
            if letter in string.digits:
                digit += 1
                advancedmask_string += "?d"
                if not simplemask or not simplemask[-1] == 'digit': simplemask.append('digit')

            elif letter in string.lowercase:
                lower += 1
                advancedmask_string += "?l"
                if not simplemask or not simplemask[-1] == 'string': simplemask.append('string')


            elif letter in string.uppercase:
                upper += 1
                advancedmask_string += "?u"
                if not simplemask or not simplemask[-1] == 'string': simplemask.append('string')

            else:
                special += 1
                advancedmask_string += "?s"
                if not simplemask or not simplemask[-1] == 'special': simplemask.append('special')


        # String representation of masks
        simplemask_string = ''.join(simplemask) if len(simplemask) <= 3 else 'othermask'

        # Policy
        policy = (digit,lower,upper,special)

        # Determine character-set
        if   digit and not lower and not upper and not special: charset = 'numeric'
        elif not digit and lower and not upper and not special: charset = 'loweralpha'
        elif not digit and not lower and upper and not special: charset = 'upperalpha'
        elif not digit and not lower and not upper and special: charset = 'special'

        elif not digit and lower and upper and not special:     charset = 'mixedalpha'
        elif digit and lower and not upper and not special:     charset = 'loweralphanum'
        elif digit and not lower and upper and not special:     charset = 'upperalphanum'
        elif not digit and lower and not upper and special:     charset = 'loweralphaspecial'
        elif not digit and not lower and upper and special:     charset = 'upperalphaspecial'
        elif digit and not lower and not upper and special:     charset = 'specialnum'

        elif not digit and lower and upper and special:         charset = 'mixedalphaspecial'
        elif digit and not lower and upper and special:         charset = 'upperalphaspecialnum'
        elif digit and lower and not upper and special:         charset = 'loweralphaspecialnum'
        elif digit and lower and upper and not special:         charset = 'mixedalphanum'
        else:                                                   charset = 'all'

        return (pass_length, charset, simplemask_string, advancedmask_string, policy)

    def generate_stats(self, filename):
        """ Generate password statistics. """

        with open(filename, 'r') as f:

            for password in f:
                password = password.rstrip('\r\n')

                if len(password) == 0: continue

                self.total_counter += 1  

                (pass_length,characterset,simplemask,advancedmask, policy) = self.analyze_password(password)
                (digit,lower,upper,special) = policy

                if (self.charsets == None    or characterset in self.charsets) and \
                   (self.simplemasks == None or simplemask in self.simplemasks) and \
                   (self.maxlength == None   or pass_length <= self.maxlength) and \
                   (self.minlength == None   or pass_length >= self.minlength):

                    self.filter_counter += 1

                    if self.mindigit == None or digit < self.mindigit: self.mindigit = digit
                    if self.maxdigit == None or digit > self.maxdigit: self.maxdigit = digit

                    if self.minupper == None or upper < self.minupper: self.minupper = upper
                    if self.maxupper == None or upper > self.maxupper: self.maxupper = upper

                    if self.minlower == None or lower < self.minlower: self.minlower = lower
                    if self.maxlower == None or lower > self.maxlower: self.maxlower = lower

                    if self.minspecial == None or special < self.minspecial: self.minspecial = special
                    if self.maxspecial == None or special > self.maxspecial: self.maxspecial = special

                    if pass_length in self.stats_length:
                        self.stats_length[pass_length] += 1
                    else:
                        self.stats_length[pass_length] = 1

                    if characterset in self.stats_charactersets:
                        self.stats_charactersets[characterset] += 1
                    else:
                        self.stats_charactersets[characterset] = 1

                    if simplemask in self.stats_simplemasks:
                        self.stats_simplemasks[simplemask] += 1
                    else:
                        self.stats_simplemasks[simplemask] = 1

                    if advancedmask in self.stats_advancedmasks:
                        self.stats_advancedmasks[advancedmask] += 1
                    else:
                        self.stats_advancedmasks[advancedmask] = 1

    def print_stats(self):
        """ Print password statistics. """

        print "[+] Analyzing %d%% (%d/%d) of passwords" % (self.filter_counter*100/self.total_counter, self.filter_counter, self.total_counter)
        print "    NOTE: Statistics below is relative to the number of analyzed passwords, not total number of passwords"
        print "\n[*] Length:"
        for (length,count) in sorted(self.stats_length.iteritems(), key=operator.itemgetter(1), reverse=True):
            if self.hiderare and not count*100/self.filter_counter > 0: continue
            print "[+] %25d: %02d%% (%d)" % (length, count*100/self.filter_counter, count)

        print "\n[*] Character-set:"
        for (char,count) in sorted(self.stats_charactersets.iteritems(), key=operator.itemgetter(1), reverse=True):
            if self.hiderare and not count*100/self.filter_counter > 0: continue
            print "[+] %25s: %02d%% (%d)" % (char, count*100/self.filter_counter, count)

        print "\n[*] Password complexity:"
        print "[+]                     digit: min(%s) max(%s)" % (self.mindigit, self.maxdigit)
        print "[+]                     lower: min(%s) max(%s)" % (self.minlower, self.maxlower)
        print "[+]                     upper: min(%s) max(%s)" % (self.minupper, self.maxupper)
        print "[+]                   special: min(%s) max(%s)" % (self.minspecial, self.maxspecial)

        print "\n[*] Simple Masks:"
        for (simplemask,count) in sorted(self.stats_simplemasks.iteritems(), key=operator.itemgetter(1), reverse=True):
            if self.hiderare and not count*100/self.filter_counter > 0: continue
            print "[+] %25s: %02d%% (%d)" % (simplemask, count*100/self.filter_counter, count)

        print "\n[*] Advanced Masks:"
        for (advancedmask,count) in sorted(self.stats_advancedmasks.iteritems(), key=operator.itemgetter(1), reverse=True):
            if count*100/self.filter_counter > 0:
                print "[+] %25s: %02d%% (%d)" % (advancedmask, count*100/self.filter_counter, count)

            if self.output_file:
                self.output_file.write("%s,%d\n" % (advancedmask,count))

if __name__ == "__main__":

    header  = "                       _ \n"
    header += "     StatsGen %s   | |\n"  % VERSION
    header += "      _ __   __ _  ___| | _\n"
    header += "     | '_ \ / _` |/ __| |/ /\n"
    header += "     | |_) | (_| | (__|   < \n"
    header += "     | .__/ \__,_|\___|_|\_\\\n"
    header += "     | |                    \n"
    header += "     |_| iphelix@thesprawl.org\n"
    header += "\n"

    parser = OptionParser("%prog [options] passwords.txt\n\nType --help for more options", version="%prog "+VERSION)

    filters = OptionGroup(parser, "Password Filters")
    filters.add_option("--minlength", dest="minlength", type="int", metavar="8", help="Minimum password length")
    filters.add_option("--maxlength", dest="maxlength", type="int", metavar="8", help="Maximum password length")
    filters.add_option("--charset", dest="charsets", help="Password charset filter (comma separated)", metavar="loweralpha,numeric")
    filters.add_option("--simplemask", dest="simplemasks",help="Password mask filter (comma separated)", metavar="stringdigit,allspecial")
    parser.add_option_group(filters)

    parser.add_option("-o", "--output", dest="output_file",help="Save masks and stats to a file", metavar="password.masks")
    parser.add_option("--hiderare", action="store_true", dest="hiderare", default=False, help="Hide statistics covering less than 1% of the sample")

    parser.add_option("-q", "--quiet", action="store_true", dest="quiet", default=False, help="Don't show headers.")
    (options, args) = parser.parse_args()

    # Print program header
    if not options.quiet:
        print header

    if len(args) != 1:
        parser.error("no passwords file specified")
        exit(1)

    print "[*] Analyzing passwords in [%s]" % args[0]

    statsgen = StatsGen()

    if not options.minlength   == None: statsgen.minlength   = options.minlength
    if not options.maxlength   == None: statsgen.maxlength   = options.maxlength
    if not options.charsets    == None: statsgen.charsets    = [x.strip() for x in options.charsets.split(',')]
    if not options.simplemasks == None: statsgen.simplemasks = [x.strip() for x in options.simplemasks.split(',')]

    if options.hiderare: statsgen.hiderare = options.hiderare

    if options.output_file:
        print "[*] Saving advanced masks and occurrences to [%s]" % options.output_file
        statsgen.output_file = open(options.output_file, 'w')

    statsgen.generate_stats(args[0])
    statsgen.print_stats()