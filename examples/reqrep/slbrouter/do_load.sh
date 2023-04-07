SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
/opt/xdp_tools/xdp-loader load -n xdp_pass_ig lb11out_out $SCRIPT_DIR/bpf_bpfel.o
/opt/xdp_tools/xdp-loader load -n xdp_pass_ig lb11in_out $SCRIPT_DIR/bpf_bpfel.o
#/opt/cmd.sh lb11 /opt/xdp_tools/xdp-loader load -n xdp_redirect_func  lb11out_in  ./minimal.bpf.o
#/opt/cmd.sh lb11 /opt/xdp_tools/xdp-loader load -n xdp_redirect_internal  lb11in_in  ./minimal.bpf.o
#/opt/cmd.sh c1 /opt/xdp_tools/xdp-loader load -n xdp_icmp c1_in ./minimal.bpf.o
bpftool net
