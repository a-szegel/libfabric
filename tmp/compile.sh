# Compile from install dir
# gcc test_rcu_link.c -o test_rcu_link -lurcu-bp -lurcu-mb -lurcu-qsbr -I $HOME/userspace-rcu/install/include -L $HOME/userspace-rcu/install/lib

# Compile from system packages
gcc test_rcu_link.c -o test_rcu_link -lurcu-bp -lurcu-mb -lurcu-qsbr