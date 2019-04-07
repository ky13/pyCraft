#!/usr/bin/env python

from __future__ import print_function

import datetime
import getpass
import json
import re
import sys
from termcolor import colored
from threading import Timer
import time
from optparse import OptionParser

from minecraft import authentication
from minecraft.exceptions import YggdrasilError
from minecraft.networking.connection import Connection
from minecraft.networking.packets import Packet, clientbound, serverbound
from minecraft.compat import input

COLOR_REPLACE = {
    'black': 'grey',
    'dark_blue': 'blue',
    'dark_green': 'green',
    'dark_aqua': 'cyan',
    'dark_red': 'red',
    'dark_purple': 'magenta',
    'gold': 'yellow',
    'gray': 'grey',
    'dark_gray': 'grey',
    'blue': 'blue',
    'green': 'green',
    'aqua': 'cyan',
    'red': 'red',
    'light_purple': 'magenta',
    'yellow': 'yellow',
    'white': 'white',
}


class RepeatedTimer(object):
    def __init__(self, interval, function, *args, **kwargs):
        self._timer     = None
        self.function   = function
        self.interval   = interval
        self.args       = args
        self.kwargs     = kwargs
        self.is_running = False
        self.start()

    def _run(self):
        self.is_running = False
        self.start()
        self.function(*self.args, **self.kwargs)

    def start(self):
        if not self.is_running:
            self._timer = Timer(self.interval, self._run)
            self._timer.start()
            self.is_running = True

    def stop(self):
        self._timer.cancel()
        self.is_running = False


class Message():

    formatted_str = ""
    plain_str = ""

    def __init__(self, data):
        self.formatted_str = self.get_formatted_text(data)
        self.plain_str = self.get_text(data)

        if type(data) == dict and 'extra' in data:
            for part in data['extra']:

                self.formatted_str += self.get_formatted_text(part)
                self.plain_str += self.get_text(part)

                if type(part) == dict and 'extra' in part:
                    for subpart in part['extra']:
                        self.formatted_str += self.get_formatted_text(subpart)
                        self.plain_str += self.get_text(subpart)


    def get_color(self, color):
        if color in COLOR_REPLACE:
            return COLOR_REPLACE[color]
        else:
            return color

    def get_text(self, part):
        if type(part) == str:
            return part
        elif 'text' in part:
            return part['text']
        else:
            return ""

    def get_formatted_text(self, part):
        if type(part) == str:
            return part
        elif 'text' in part:
            if 'color' in part:
                return colored(part['text'], self.get_color(part['color']))
            else:
                return part['text']
        else:
            return ""

    def __contains__(self, pattern):
        return re.search(pattern, self.plain_str)


def get_options():
    parser = OptionParser()

    parser.add_option("-u", "--username", dest="username", default=None,
                      help="username to log in with")

    parser.add_option("-p", "--password", dest="password", default=None,
                      help="password to log in with")

    parser.add_option("-s", "--server", dest="server", default=None,
                      help="server host or host:port "
                           "(enclose IPv6 addresses in square brackets)")

    parser.add_option("-r", "--realm", dest="realm", default=None,
                      help="realm name")

    parser.add_option("-o", "--offline", dest="offline", action="store_true",
                      help="connect to a server in offline mode "
                           "(no password required)")

    parser.add_option("-d", "--dump-packets", dest="dump_packets",
                      action="store_true",
                      help="print sent and received packets to standard error")

    (options, args) = parser.parse_args()

    if not options.username:
        options.username = input("Enter your username: ")

    if not options.password and not options.offline:
        options.password = getpass.getpass("Enter your password (leave "
                                           "blank for offline mode): ")
        options.offline = options.offline or (options.password == "")

    if not options.server:
        options.server = input("Enter server host or host:port "
                               "(enclose IPv6 addresses in square brackets): ")
    # Try to split out port and address
    match = re.match(r"((?P<host>[^\[\]:]+)|\[(?P<addr>[^\[\]]+)\])"
                     r"(:(?P<port>\d+))?$", options.server)
    if match is None:
        raise ValueError("Invalid server address: '%s'." % options.server)
    options.address = match.group("host") or match.group("addr")
    options.port = int(match.group("port") or 25565)

    if not options.realm:
        options.username = input("Enter your realm: ")

    return options


def main():
    options = get_options()

    if options.offline:
        print("Connecting in offline mode...")
        connection = Connection(
            options.address, options.port, username=options.username)
    else:
        auth_token = authentication.AuthenticationToken()
        try:
            auth_token.authenticate(options.username, options.password)
        except YggdrasilError as e:
            print(e)
            sys.exit()
        print("Logged in as %s..." % auth_token.username)
        connection = Connection(
            options.address, options.port, auth_token=auth_token)

    if options.dump_packets:
        def print_incoming(packet):
            if type(packet) is Packet:
                # This is a direct instance of the base Packet type, meaning
                # that it is a packet of unknown type, so we do not print it.
                return
            print('--> %s' % packet, file=sys.stderr)

        def print_outgoing(packet):
            print('<-- %s' % packet, file=sys.stderr)

        connection.register_packet_listener(
            print_incoming, Packet, early=True)
        connection.register_packet_listener(
            print_outgoing, Packet, outgoing=True)

    def handle_join_game(join_game_packet):
        print('Connected.')

    connection.register_packet_listener(
        handle_join_game, clientbound.play.JoinGamePacket)

    def print_chat(chat_packet, output="default"):

        if output == "raw":
            print("Message (%s): %s" % (
                chat_packet.field_string('position'), chat_packet.json_data))

        chat_json = json.loads(chat_packet.json_data)

        if output == "pretty":
            print(json.dumps(chat_json, sort_keys=True, indent=4, separators=(',', ': ')))

        if output == "default":
            message = Message(chat_json)
            ts = datetime.datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S')
            print("[{}] {}".format(colored(ts, "grey"), message.formatted_str))

    connection.register_packet_listener(
        print_chat, clientbound.play.ChatMessagePacket)

    connection.connect()

    def requeue(realm):
        message = "/joinqueue " + realm
        packet = serverbound.play.ChatPacket()
        packet.message = message
        print(message)
        connection.write_packet(packet)

    # Re-join realm every 60 seconds
    rt = RepeatedTimer(60, requeue, options.realm)

    while True:
        try:
            text = input()
            if text == "/respawn":
                print("respawning...")
                packet = serverbound.play.ClientStatusPacket()
                packet.action_id = serverbound.play.ClientStatusPacket.RESPAWN
                connection.write_packet(packet)
            else:
                packet = serverbound.play.ChatPacket()
                packet.message = text
                connection.write_packet(packet)
        except KeyboardInterrupt:
            rt.stop()
            print("Bye!")
            sys.exit()


if __name__ == "__main__":
    main()

