#!/usr/bin/env python3

class BindingHid:
    def __init__(self, vendor, product):
        import hid
        try:
            self.dev = hid.Device(vendor, product)
        except hid.HIDException:
            print(f"Could not open device {vendor:04X}:{product:04X}. Check that /dev/hidraw* is accessible\n")
            raise
    def send_feature_report(self, buffer):
        self.dev.send_feature_report(buffer)
    def close(self):
        self.dev.close()

class BindingHidraw:
    def __init__(self, vendor, product):
        import hidraw
        self.dev = hidraw.device()
        try:
            self.dev.open(vendor, product)
        except OSError:
            print(f"Could not open device {vendor:04X}:{product:04X}. Check that /dev/hidraw* is accessible\n")
            raise
    def send_feature_report(self, buffer):
        self.dev.send_feature_report(buffer)
    def close(self):
        self.dev.close()

class BindingHidapi:
    def __init__(self, vendor, product):
        import hid
        self.dev = hid.device()
        try:
            self.dev.open(vendor, product)
        except OSError:
            print(f"Could not open device {vendor:04X}:{product:04X}. Check that /dev/hidraw* is accessible\n")
            raise
    def send_feature_report(self, buffer):
        self.dev.send_feature_report(buffer)
    def close(self):
        self.dev.close()

class BindingHidapiCffi:
    def __init__(self, vendor, product):
        import hidapi
        try:
            self.dev = hidapi.Device(vendor_id=vendor, product_id=product)
        except OSError:
            print(f"Could not open device {vendor:04X}:{product:04X}. Check that /dev/hidraw* is accessible")
            print("If libusb support for libhidapi is installed (e.g. the libhidapi-libusb0 package)")
            print("the hidapi-cffi binding may be broken; try installing another hidapi binding.\n")
            raise
    def send_feature_report(self, buffer):
        self.dev.send_feature_report(buffer[1:], buffer[:1])
    def close(self):
        self.dev.close()

def get_binding():
    try:
        import hidraw
        return BindingHidraw
    except ModuleNotFoundError:
        try:
            import hid
            if "Device" in hid.__dict__:
                return BindingHid
            else:
                return BindingHidapi
        except ModuleNotFoundError:
            try:
                import hidapi
                return BindingHidapiCffi
            except ModuleNotFoundError:
                print("Needs hidapi bindings (hid or hidapi or hidapi-cffi on pip)\n")
                raise

import sys

Hid = get_binding()

if len(sys.argv) < 2:
    print("Usage: kb-bl.py BRIGHTNESS [FNLOCK]")
    print("0 is off, -1 is unchanged, 3 is max brightness.")
    print("For FNLOCK, 1 means top row is plain F-keys.")
    exit(1)

cmds = []

# Setup commands; not required if using the BPF program
if True:
    cmds.append(f"5a0520310008")
    cmds.append(f"5ad08f01")

if len(sys.argv) > 1:
    brightness = int(sys.argv[1])
    brightness = min(max(brightness, -1), 3)

    if brightness != -1:
        cmds.append(f"5abac5c4{brightness:02x}")

if len(sys.argv) > 2:
    fn_lock = int(sys.argv[2])
    fn_lock = min(max(fn_lock, 0), 1)

    cmds.append(f"5ad04e{fn_lock:02x}")

device = Hid(0x0B05, 0x4543)

for cmd in cmds:
    c = bytes.fromhex(cmd)
    c = c + b'\0' * (64 - len(c))
    device.send_feature_report(c)

device.close()
