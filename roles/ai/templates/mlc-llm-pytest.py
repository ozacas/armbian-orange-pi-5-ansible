#!/usr/bin/python3
# ref: https://github.com/Chrisz236/llm-rk3588
from mlc_llm import ChatModule
from mlc_llm.callback import StreamToStdout

cm = ChatModule(
     model="{{prebuilt_dir}}/Llama-3-8B-Instruct-q4f16_1-MLC",
     model_lib_path="{{prebuilt_dir}}/Llama-3-8B-Instruct-q4f16_1-mali.so",
     device="opencl"
 )

# Generate a response for a given prompt
cm.generate(prompt="What is the meaning of life?", progress_callback=StreamToStdout(callback_interval=2))
# Print prefill and decode performance statistics
print(f"Statistics: {cm.stats()}\n")
exit(0)
