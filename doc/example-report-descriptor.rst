:orphan:

.. _example_report_descriptor:

Example HID Report Descriptor
=============================

This report descriptor is used in the :ref:`tutorial`::

   # Microsoft Microsoft® 2.4GHz Transceiver v9.0
   # 0x05, 0x01,                    // Usage Page (Generic Desktop)        0
   # 0x09, 0x02,                    // Usage (Mouse)                       2
   # 0xa1, 0x01,                    // Collection (Application)            4
   # 0x05, 0x01,                    //  Usage Page (Generic Desktop)       6
   # 0x09, 0x02,                    //  Usage (Mouse)                      8
   # 0xa1, 0x02,                    //  Collection (Logical)               10
   # 0x85, 0x1a,                    //   Report ID (26)                    12
   # 0x09, 0x01,                    //   Usage (Pointer)                   14
   # 0xa1, 0x00,                    //   Collection (Physical)             16
   # 0x05, 0x09,                    //    Usage Page (Button)              18
   # 0x19, 0x01,                    //    Usage Minimum (1)                20
   # 0x29, 0x05,                    //    Usage Maximum (5)                22
   # 0x95, 0x05,                    //    Report Count (5)                 24
   # 0x75, 0x01,                    //    Report Size (1)                  26
   # 0x15, 0x00,                    //    Logical Minimum (0)              28
   # 0x25, 0x01,                    //    Logical Maximum (1)              30
   # 0x81, 0x02,                    //    Input (Data,Var,Abs)             32
   # 0x75, 0x03,                    //    Report Size (3)                  34
   # 0x95, 0x01,                    //    Report Count (1)                 36
   # 0x81, 0x01,                    //    Input (Cnst,Arr,Abs)             38
   # 0x05, 0x01,                    //    Usage Page (Generic Desktop)     40
   # 0x09, 0x30,                    //    Usage (X)                        42
   # 0x09, 0x31,                    //    Usage (Y)                        44
   # 0x95, 0x02,                    //    Report Count (2)                 46
   # 0x75, 0x10,                    //    Report Size (16)                 48
   # 0x16, 0x01, 0x80,              //    Logical Minimum (-32767)         50
   # 0x26, 0xff, 0x7f,              //    Logical Maximum (32767)          53
   # 0x81, 0x06,                    //    Input (Data,Var,Rel)             56
   # 0xa1, 0x02,                    //    Collection (Logical)             58
   # 0x85, 0x12,                    //     Report ID (18)                  60
   # 0x09, 0x48,                    //     Usage (Resolution Multiplier)   62
   # 0x95, 0x01,                    //     Report Count (1)                64
   # 0x75, 0x02,                    //     Report Size (2)                 66
   # 0x15, 0x00,                    //     Logical Minimum (0)             68
   # 0x25, 0x01,                    //     Logical Maximum (1)             70
   # 0x35, 0x01,                    //     Physical Minimum (1)            72
   # 0x45, 0x0c,                    //     Physical Maximum (12)           74
   # 0xb1, 0x02,                    //     Feature (Data,Var,Abs)          76
   # 0x85, 0x1a,                    //     Report ID (26)                  78
   # 0x09, 0x38,                    //     Usage (Wheel)                   80
   # 0x35, 0x00,                    //     Physical Minimum (0)            82
   # 0x45, 0x00,                    //     Physical Maximum (0)            84
   # 0x95, 0x01,                    //     Report Count (1)                86
   # 0x75, 0x10,                    //     Report Size (16)                88
   # 0x16, 0x01, 0x80,              //     Logical Minimum (-32767)        90
   # 0x26, 0xff, 0x7f,              //     Logical Maximum (32767)         93
   # 0x81, 0x06,                    //     Input (Data,Var,Rel)            96
   # 0xc0,                          //    End Collection                   98
   # 0xa1, 0x02,                    //    Collection (Logical)             99
   # 0x85, 0x12,                    //     Report ID (18)                  101
   # 0x09, 0x48,                    //     Usage (Resolution Multiplier)   103
   # 0x75, 0x02,                    //     Report Size (2)                 105
   # 0x15, 0x00,                    //     Logical Minimum (0)             107
   # 0x25, 0x01,                    //     Logical Maximum (1)             109
   # 0x35, 0x01,                    //     Physical Minimum (1)            111
   # 0x45, 0x0c,                    //     Physical Maximum (12)           113
   # 0xb1, 0x02,                    //     Feature (Data,Var,Abs)          115
   # 0x35, 0x00,                    //     Physical Minimum (0)            117
   # 0x45, 0x00,                    //     Physical Maximum (0)            119
   # 0x75, 0x04,                    //     Report Size (4)                 121
   # 0xb1, 0x01,                    //     Feature (Cnst,Arr,Abs)          123
   # 0x85, 0x1a,                    //     Report ID (26)                  125
   # 0x05, 0x0c,                    //     Usage Page (Consumer Devices)   127
   # 0x95, 0x01,                    //     Report Count (1)                129
   # 0x75, 0x10,                    //     Report Size (16)                131
   # 0x16, 0x01, 0x80,              //     Logical Minimum (-32767)        133
   # 0x26, 0xff, 0x7f,              //     Logical Maximum (32767)         136
   # 0x0a, 0x38, 0x02,              //     Usage (AC Pan)                  139
   # 0x81, 0x06,                    //     Input (Data,Var,Rel)            142
   # 0xc0,                          //    End Collection                   144
   # 0xc0,                          //   End Collection                    145
   # 0xc0,                          //  End Collection                     146
   # 0xc0,                          // End Collection                      147
   # 0x05, 0x0c,                    // Usage Page (Consumer Devices)       148
   # 0x09, 0x01,                    // Usage (Consumer Control)            150
   # 0xa1, 0x01,                    // Collection (Application)            152
   # 0x05, 0x01,                    //  Usage Page (Generic Desktop)       154
   # 0x09, 0x02,                    //  Usage (Mouse)                      156
   # 0xa1, 0x02,                    //  Collection (Logical)               158
   # 0x85, 0x1f,                    //   Report ID (31)                    160
   # 0x05, 0x0c,                    //   Usage Page (Consumer Devices)     162
   # 0x0a, 0x38, 0x02,              //   Usage (AC Pan)                    164
   # 0x95, 0x01,                    //   Report Count (1)                  167
   # 0x75, 0x10,                    //   Report Size (16)                  169
   # 0x16, 0x01, 0x80,              //   Logical Minimum (-32767)          171
   # 0x26, 0xff, 0x7f,              //   Logical Maximum (32767)           174
   # 0x81, 0x06,                    //   Input (Data,Var,Rel)              177
   # 0x85, 0x17,                    //   Report ID (23)                    179
   # 0x06, 0x00, 0xff,              //   Usage Page (Vendor Defined Page 1) 181
   # 0x0a, 0x06, 0xff,              //   Usage (Vendor Usage 0xff06)       184
   # 0x0a, 0x0f, 0xff,              //   Usage (Vendor Usage 0xff0f)       187
   # 0x15, 0x00,                    //   Logical Minimum (0)               190
   # 0x25, 0x01,                    //   Logical Maximum (1)               192
   # 0x35, 0x01,                    //   Physical Minimum (1)              194
   # 0x45, 0x0c,                    //   Physical Maximum (12)             196
   # 0x95, 0x02,                    //   Report Count (2)                  198
   # 0x75, 0x02,                    //   Report Size (2)                   200
   # 0xb1, 0x02,                    //   Feature (Data,Var,Abs)            202
   # 0x0a, 0x04, 0xff,              //   Usage (Vendor Usage 0xff04)       204
   # 0x35, 0x00,                    //   Physical Minimum (0)              207
   # 0x45, 0x00,                    //   Physical Maximum (0)              209
   # 0x95, 0x01,                    //   Report Count (1)                  211
   # 0x75, 0x01,                    //   Report Size (1)                   213
   # 0xb1, 0x02,                    //   Feature (Data,Var,Abs)            215
   # 0x75, 0x03,                    //   Report Size (3)                   217
   # 0xb1, 0x01,                    //   Feature (Cnst,Arr,Abs)            219
   # 0xc0,                          //  End Collection                     221
   # 0xc0,                          // End Collection                      222
   #
   R: 223 05 01 09 02 a1 01 05 01 09 02 a1 02 85 1a 09 01 a1 00 05 09 19 01 29 05 95 05 75 01 15 00 25 01 81 02 75 03 95 01 81 01 05 01 09 30 09 31 95 02 75 10 16 01 80 26 ff 7f 81 06 a1 02 85 12 09 48 95 01 75 02 15 00 25 01 35 01 45 0c b1 02 85 1a 09 38 35 00 45 00 95 01 75 10 16 01 80 26 ff 7f 81 06 c0 a1 02 85 12 09 48 75 02 15 00 25 01 35 01 45 0c b1 02 35 00 45 00 75 04 b1 01 85 1a 05 0c 95 01 75 10 16 01 80 26 ff 7f 0a 38 02 81 06 c0 c0 c0 c0 05 0c 09 01 a1 01 05 01 09 02 a1 02 85 1f 05 0c 0a 38 02 95 01 75 10 16 01 80 26 ff 7f 81 06 85 17 06 00 ff 0a 06 ff 0a 0f ff 15 00 25 01 35 01 45 0c 95 02 75 02 b1 02 0a 04 ff 35 00 45 00 95 01 75 01 b1 02 75 03 b1 01 c0 c0
   N: Microsoft Microsoft® 2.4GHz Transceiver v9.0
   I: 3 045e 07a5

Note that this device has multiple HID interfaces, only this report descriptor
(on the second interface) is used in the tutorial.
