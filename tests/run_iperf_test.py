# -*- coding: utf-8 -*-
#!/usr/bin/python

"""
Skrypt pomocniczy do uruchamiania z poziomu Mininet CLI.
Generuje wiele równoległych przepływów iperf w celu przetestowania
kontrolera FAMTAR.

Aby uruchomić, w konsoli Mininet wpisz:
mininet> source run_iperf_test.py
"""

from mininet.cli import CLI
from mininet.net import Mininet

# --- Konfiguracja testu ---
NUM_FLOWS = 20       # Liczba równoległych sesji iperf
TARGET_IP = '10.0.0.4' # Adres IP hosta docelowego (serwera)
SOURCE_HOST = 'h1'   # Nazwa hosta źródłowego (klienta)
TARGET_HOST = 'h4'   # Nazwa hosta docelowego (serwera)
DURATION = 250       # Czas trwania każdej sesji iperf w sekundach

def run_test(net):
    """
    Funkcja pobiera obiekt sieci 'net' z Mininet i wykonuje na nim komendy.
    """
    print("*** Uruchamianie serwera iperf na hoście %s" % TARGET_HOST)
    target = net.get(TARGET_HOST)
    # Uruchom serwer iperf w tle
    target.cmd('iperf -s &')

    print("*** Uruchamianie %d klientów iperf na hoście %s" % (NUM_FLOWS, SOURCE_HOST))
    source = net.get(SOURCE_HOST)
    for i in range(NUM_FLOWS):
        # Budujemy i wykonujemy komendę dla każdego klienta iperf w tle
        cmd = 'iperf -c %s -t %d &' % (TARGET_IP, DURATION)
        source.cmd(cmd)
        print("  -> Uruchomiono klienta %d" % (i + 1))

    print("*** Test uruchomiony. Wszystkie %d przepływów działa w tle." % NUM_FLOWS)

# Ten fragment pozwala na uruchomienie skryptu bezpośrednio w Mininet
# poprzez komendę 'py' lub 'source'. Mininet automatycznie przekaże
# obiekt 'net' do funkcji 'run_test'.
# Niestety, standardowy 'source' nie działa w ten sposób, więc
# trzeba będzie użyć komendy 'py'
# mininet> py net.run(run_test)
