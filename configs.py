import json

CFG = {
    "directory": {
        "logs_dir": "logs/",
        "node_files_dir": "node_files/",
        "tracker_db_dir": "tracker_DB/",
    },
    "constants": {
        "AVAILABLE_PORTS_RANGE": (1024, 65535),
        "TRACKER_ADDR": ("192.168.0.112", 12345), #change to tracker's IP
        "TRACKER_ADDR_PROXY": ("192.168.0.112", 12367),#change to tracker's IP
        "TRACKER_PORT_LISTEN": 23456,
        "tracker_update_port": 12390,
        "BUFFER_SIZE": 8192, 
        "CHUNK_PIECES_SIZE": 2000, 
        "MAX_SPLITTNES_RATE": 3,   
        "NODE_TIME_INTERVAL": 20,       
        "TRACKER_TIME_INTERVAL": 22     
    },
    "tracker_requests_mode": {
        "REGISTER": 0,  
        "OWN": 1,      
        "START": 2,      
        "UPDATE": 3,   
        "STOP": 4,      
        "ENTER": 5       
    }
}

class Config:
    def __init__(self, directory, constants, tracker_requests_mode):
        self.directory = directory
        self.constants = constants
        self.tracker_requests_mode = tracker_requests_mode

    @classmethod
    def from_json(cls, cfg):
        params = json.loads(json.dumps(cfg), object_hook=HelperObject)
        return cls(params.directory, params.constants, params.tracker_requests_mode)

class HelperObject(object):
    def __init__(self, dict_):
        self.__dict__.update(dict_)