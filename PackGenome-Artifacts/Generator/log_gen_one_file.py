import json
import os
from LogGeneration import log_generate
with open("./config/GenConfig.json") as f:
    configs = json.load(f)
samples = ["MMK_upx(32bit).exe"]
samples_dir = r"E:\NT230\coursework\MMK"
log_generate(configs, samples_dir, samples)
    