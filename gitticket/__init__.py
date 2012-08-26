#!/usr/bin/env python
# -*- coding:utf-8 -*-
def main():
    import argparse
    from gitticket import cmd
    psr = argparse.ArgumentParser(description='Welcome to git-ticket!!')
    subpsr = psr.add_subparsers(help='commands')
    psr_show = subpsr.add_parser('show', help='')
    psr_list = subpsr.add_parser('list', help='')
    psr_mine = subpsr.add_parser('mine', help='')
    psr_commit = subpsr.add_parser('commit', help='')
    psr_add = subpsr.add_parser('add', help='')
    psr_update = subpsr.add_parser('update', help='')
    psr_local = subpsr.add_parser('local', help='')
    #
    psr_show.set_defaults(cmd=cmd.show)
    psr_list.set_defaults(cmd=cmd.list)
    psr_mine.set_defaults(cmd=cmd.mine)
    psr_commit.set_defaults(cmd=cmd.commit)
    psr_add.set_defaults(cmd=cmd.add)
    psr_update.set_defaults(cmd=cmd.update)
    psr_local.set_defaults(cmd=cmd.local)
    opts = psr.parse_args()
    opts.cmd(vars(opts))
