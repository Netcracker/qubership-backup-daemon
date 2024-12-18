# Copyright 2024-2025 NetCracker Technology Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

config = None


class Config:
    def __init__(self, configuration):
        self.databases_key = configuration['databases_key']
        self.dbmap_key = configuration['dbmap_key']
        self.enable_full_restore = configuration['enable_full_restore']
        self.custom_vars = configuration['custom_vars']
        self.publish_custom_vars = configuration['publish_custom_vars']
        self.logs_to_stdout = configuration['logs_to_stdout']
