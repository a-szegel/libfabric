#!/bin/python3
# source ~/env/bin/activate to get PF's env
# This script needs to be kicked off on the server IP's host
from matplotlib import pyplot as plt
from PortaFiducia.tests.utils import run_command
import subprocess
from time import sleep


# Configurable server IP (in case we change instances)
sever_ip = "172.31.74.62"
client_ip = "172.31.65.25"
iterations = 2000000
warmup_iterations = 100

# Step 1: Compile Libfabric ~20s
print("Compile libfabric and fabtests:")
autogen = "./autogen.sh"
configure = "./configure --prefix=$HOME/libfabric/install --disable-verbs --disable-psm3 --disable-opx --disable-usnic --disable-rstream --enable-efa --with-cuda=/usr/local/cuda --enable-cuda-dlopen --with-gdrcopy --enable-gdrcopy-dlopen"
clean = "rm -rf $HOME/libfabric/install && make clean"
install = "make -j install"
run_command(f"cd $HOME/libfabric; {autogen} && {configure} && {clean} && {install}")

# Step 2: Compile Fabtests ~10s
configure = "./configure --prefix=$HOME/libfabric/fabtests/install --with-libfabric=$HOME/libfabric/install --with-cuda=/usr/local/cuda"
clean = "rm -rf $HOME/libfabric/fabtests/install && make clean"
run_command(f"cd $HOME/libfabric/fabtests; {autogen} && {configure} && {clean} && {install}")


# Step 3: Run fi_rdm_pingpong
print("\n\n Running Eager Send Data Tests \n\n")

executable = "/home/ec2-user/libfabric/fabtests/install/bin/fi_rdm_pingpong"
server_args = f" --pin-core 1 -i 0 -p efa -D cuda -w {warmup_iterations} -I {iterations} -S 1024 -E "
server_command = executable + server_args
client_command = "ssh " + client_ip + " " + executable + server_args + sever_ip

print(f"Running Server Command: {server_command}")
print(f"Running Client Command: {client_command}")
server_process = subprocess.Popen(server_command, stdout=subprocess.PIPE, stderr=None,
                                  shell=True, universal_newlines=True)
sleep(5)

client_process = subprocess.Popen(client_command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                  shell=True, universal_newlines=True)

sleep(5)

try:
    _, _ = server_process.communicate(timeout=720)
    sleep(5)
    _, _ = client_process.communicate(timeout=720)
except subprocess.TimeoutExpired:
    server_process.terminate()
    client_process.terminate()
    raise RuntimeError("Client/Server Timed Out")


def parse_rdm_pingpong_output(filename):
    libfabric_to_rdma_core = []
    rdma_core = []
    rdma_core_to_libfabric = []
    post_recv_buff = []
    empty_cq_progress = []
    fruitful_cq_progress = []
    fruitful_cq_progress_num_completions = []

    with open(filename, "r") as f:
        lines = f.readlines()

    for line in lines:
        if line.startswith("<fi_senddata> libfabric to rdma_core"):
            data = line.strip().split(" ")
            libfabric_to_rdma_core.append(int(data[5].strip(",")))
            rdma_core.append(int(data[8].strip(",")))
            rdma_core_to_libfabric.append(int(data[-1]))

        elif line.startswith("<fi_senddata> post recv buff"):
            post_recv_buff.append(int(line.strip().split(" ")[-1]))

        elif line.startswith("<fi_senddata> empty cq progress"):
            empty_cq_progress.append(int(line.strip().split(" ")[-1]))

        elif line.startswith("<fi_senddata> fruitful cq progress"):
            fruitful_cq_progress.append(int(line.strip().split(" ")[-1]))

        elif line.startswith("<fi_senddata> num completion events in fruitful progress"):
            fruitful_cq_progress_num_completions.append(int(line.strip().split(" ")[-1]))

    return libfabric_to_rdma_core, rdma_core, rdma_core_to_libfabric, post_recv_buff, empty_cq_progress, fruitful_cq_progress, fruitful_cq_progress_num_completions

(server_libfabric_to_rdma_core, server_rdma_core, server_rdma_core_to_libfabric,
 server_post_recv_buff, server_empty_cq_progress, server_fruitful_cq_progress,
 server_fruitful_cq_progress_num_completions) = parse_rdm_pingpong_output("/home/ec2-user/libfabric/server_fi_senddata_output.txt")
(client_libfabric_to_rdma_core, client_rdma_core, client_rdma_core_to_libfabric,
 client_post_recv_buff, client_empty_cq_progress, client_fruitful_cq_progress,
 client_fruitful_cq_progress_num_completions) = parse_rdm_pingpong_output("/home/ec2-user/libfabric/client_fi_senddata_output.txt")

print("\n")

# Step 3: Get/print statistics

def get_and_print_statistics(vector, name):
    import statistics
    avg = statistics.mean(vector)
    num_outliers = sum(i > avg * 5 for i in vector)
    # TODO Remove this logic
    # Remove outliers from vector
    vector = [i for i in vector if i <= avg * 5]

    # get a new average
    avg = statistics.mean(vector)
    pstd = statistics.pstdev(vector)
    minimum = min(vector)
    maximum = max(vector)
    median = sorted(vector)[len(vector) // 2]
    num_samples = len(vector)
    unique = len(set(vector))

    unit = "ns"
    if "fruitful cq progress num completion" in name:
        unit = None

    print(f"{name} average {unit}: {avg}, pstd: {pstd}, min: {minimum}, max: {maximum}, median: {median}, num_samples: {num_samples}, unique: {unique}, num_outliers removed (5x mean): {num_outliers}")

    if "fruitful cq progress num completion" in name:
        # num completions is usually always 1, no hist
        return

    plt.figure()
    plt.hist(vector, round(unique/5), range=[minimum-10, avg*2], align='mid')
    plt.title(name)
    plt.xlabel("Time (ns)")
    plt.ylabel("Frequency")
    plt.savefig(f"/home/ec2-user/libfabric/plots/{name}.png")
    plt.close()


print("Server's fi_senddata stats:")
get_and_print_statistics(server_libfabric_to_rdma_core, "Server fi_senddata libfabric to rdma_core")
get_and_print_statistics(server_rdma_core, "Server fi_senddata rdma_core")
get_and_print_statistics(server_rdma_core_to_libfabric, "Server fi_senddata rdma_core to libfabric")
get_and_print_statistics(server_post_recv_buff, "Server fi_senddata post recv buff")
get_and_print_statistics(server_empty_cq_progress, "Server fi_senddata empty cq progress")
get_and_print_statistics(server_fruitful_cq_progress, "Server fi_senddata fruitful cq progress")
get_and_print_statistics(server_fruitful_cq_progress_num_completions, "Server fi_senddata fruitful cq progress num completion")

print("\n")

print("Client's fi_senddata stats:")
get_and_print_statistics(client_libfabric_to_rdma_core, "Client fi_senddata libfabric to rdma_core")
get_and_print_statistics(client_rdma_core, "Client fi_senddata rdma_core")
get_and_print_statistics(client_rdma_core_to_libfabric, "Client fi_senddata rdma_core to libfabric")
get_and_print_statistics(client_post_recv_buff, "Client fi_senddata post recv buff")
get_and_print_statistics(client_empty_cq_progress, "Client fi_senddata empty cq progress")
get_and_print_statistics(client_fruitful_cq_progress, "Client fi_senddata fruitful cq progress")
get_and_print_statistics(client_fruitful_cq_progress_num_completions, "Client fi_senddata fruitful cq progress num completion")


# # Step 4: Run fi_rdm_rma_pingpong
# print("\n\n Running RMA Write Data Tests \n\n")
# executable = "/home/ec2-user/libfabric/fabtests/install/bin/fi_rma_pingpong"
# server_args = f" --pin-core 1 -i 0 -o writedata -p efa -D cuda -w {warmup_iterations} -I {iterations} -S 131072 -E "
# server_command = executable + server_args
# client_command = "ssh " + client_ip + " " + executable + server_args + sever_ip

# print(f"Running Server Command: {server_command}")
# print(f"Running Client Command: {client_command}")
# server_process = subprocess.Popen(server_command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
#                                   shell=True, universal_newlines=True)

# sleep(5)

# client_process = subprocess.Popen(client_command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
#                                   shell=True, universal_newlines=True)

# sleep(5)

# try:
#     server_output, _ = server_process.communicate(timeout=720)
#     sleep(5)
#     client_output, _ = client_process.communicate(timeout=720)
# except subprocess.TimeoutExpired:
#     server_process.terminate()
#     client_process.terminate()
#     raise RuntimeError("Client/Server Timed Out")

# def parse_rma_pingpong_output(filename):
#     libfabric_to_rdma_core = []
#     rdma_core = []
#     rdma_core_to_libfabric = []
#     empty_cq_progress = []
#     fruitful_cq_progress = []
#     fruitful_cq_progress_num_completions = []

#     with open(filename, "r") as f:
#         lines = f.readlines()

#     for line in lines:
#         if line.startswith("<fi_write> libfabric to rdma_core"):
#             data = line.strip().split(" ")
#             libfabric_to_rdma_core.append(int(data[5].strip(",")))
#             rdma_core.append(int(data[8].strip(",")))
#             rdma_core_to_libfabric.append(int(data[-1]))

#         elif line.startswith("<fi_write> empty cq progress"):
#             empty_cq_progress.append(int(line.strip().split(" ")[-1]))

#         elif line.startswith("<fi_write> fruitful cq progress"):
#             fruitful_cq_progress.append(int(line.strip().split(" ")[-1]))

#         elif line.startswith("<fi_write> num completion events in fruitful progress"):
#             fruitful_cq_progress_num_completions.append(int(line.strip().split(" ")[-1]))

#     return libfabric_to_rdma_core, rdma_core, rdma_core_to_libfabric, empty_cq_progress, fruitful_cq_progress, fruitful_cq_progress_num_completions

# (server_libfabric_to_rdma_core, server_rdma_core, server_rdma_core_to_libfabric,
#  server_empty_cq_progress, server_fruitful_cq_progress,
#  server_fruitful_cq_progress_num_completions) = parse_rma_pingpong_output("/home/ec2-user/libfabric/server_fi_writedata_output.txt")
# (client_libfabric_to_rdma_core, client_rdma_core, client_rdma_core_to_libfabric,
#  client_empty_cq_progress, client_fruitful_cq_progress,
#  client_fruitful_cq_progress_num_completions) = parse_rma_pingpong_output("/home/ec2-user/libfabric/client_fi_writedata_output.txt")


# print("\n")

# # Setp 5: Get/print statistics
# print("Server's fi_writedata stats:")
# get_and_print_statistics(server_libfabric_to_rdma_core, "Server fi_writedata libfabric to rdma_core")
# get_and_print_statistics(server_rdma_core, "Server fi_writedata rdma_core")
# get_and_print_statistics(server_rdma_core_to_libfabric, "Server fi_writedata rdma_core to libfabric")
# get_and_print_statistics(server_empty_cq_progress, "Server fi_writedata empty cq progress")
# get_and_print_statistics(server_fruitful_cq_progress, "Server fi_writedata fruitful cq progress")
# get_and_print_statistics(server_fruitful_cq_progress_num_completions, "Server fi_writedata fruitful cq progress num completion")

# print("\n")
# print("Client's fi_writedata stats:")
# get_and_print_statistics(client_libfabric_to_rdma_core, "Client fi_writedata libfabric to rdma_core")
# get_and_print_statistics(client_rdma_core, "Client fi_writedata rdma_core")
# get_and_print_statistics(client_rdma_core_to_libfabric, "Client fi_writedata rdma_core to libfabric")
# get_and_print_statistics(client_empty_cq_progress, "Client fi_writedata empty cq progress")
# get_and_print_statistics(client_fruitful_cq_progress, "Client fi_writedata fruitful cq progress")
# get_and_print_statistics(client_fruitful_cq_progress_num_completions, "Client fi_writedata fruitful cq progress num completion")
