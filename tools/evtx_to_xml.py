#!/usr/bin/env python3
"""Render a .evtx file to XML, one <Event> block per line.

Usage: python3 evtx_to_xml.py fichier.evtx > fichier.xml

Le paquet python-evtx expose des scripts console (evtx_dump,
evtx_dump_json) qui plantent au premier appel
(ModuleNotFoundError: No module named 'scripts'). Contournement :
appeler directement l'API Evtx.Evtx / Evtx.Views.
"""
import sys

from Evtx.Evtx import Evtx
from Evtx.Views import evtx_file_xml_view

with Evtx(sys.argv[1]) as evtx:
    for xml, record in evtx_file_xml_view(evtx.get_file_header()):
        print(xml)
