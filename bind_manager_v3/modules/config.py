#!/usr/bin/env python2

import ConfigParser

class configuration():
    def __init__(self, configuration_file):
        self.configuration_file = configuration_file


    def get_options(self):
        result_dict = {}
        Config = ConfigParser.ConfigParser()
        Config.read(self.configuration_file)
        for section in Config.sections():
            for option in Config.options(section):
                result_dict[option] = Config.get(section, option)

        return result_dict


