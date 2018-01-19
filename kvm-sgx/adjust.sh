sudo make modules_install SUBDIR=arch/x86/kvm
sudo rmmod kvm_intel
sudo rmmod kvm  
sudo insmod arch/x86/kvm/kvm.ko
sudo insmod arch/x86/kvm/kvm-intel.ko
