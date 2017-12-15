#!/usr/bin/env python3

import yaml
import logging

class Config(dict):
    "provides access to config settings"
    def __init__(self, configfile="config.yml"):
        self._loaded = False
        self.configfile = configfile

    def load(self):
        "read config from file"
        try:
            with open(self.configfile, 'r') as c:
                newconfig = yaml.safe_load(c)
                self.clear()
                self.update(newconfig)
            logging.info("loaded " + self.configfile)
            self._loaded = True
        except:
            logging.error("failed to load " + self.configfile)
            self._loaded = False
        return self._loaded
