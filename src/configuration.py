config = None


class Config:
    def __init__(self, configuration):
        self.databases_key = configuration['databases_key']
        self.dbmap_key = configuration['dbmap_key']
        self.enable_full_restore = configuration['enable_full_restore']
        self.custom_vars = configuration['custom_vars']
        self.publish_custom_vars = configuration['publish_custom_vars']
        self.logs_to_stdout = configuration['logs_to_stdout']
