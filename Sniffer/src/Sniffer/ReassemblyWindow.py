import wx
from scapy.all import *


class ReassemblyWindow(wx.Frame):
    def __init__(self, parent, type, packet_bin):
        wx.Frame.__init__(self, parent=parent, size=(600, 400), title=type,
                          style=wx.CAPTION | wx.CLOSE_BOX | wx.FRAME_FLOAT_ON_PARENT)
        self.parent = parent

        if type == 'IP':
            self.packet = IP(packet_bin[0])
        elif type == 'IPv6':
            self.packet = IPv6(packet_bin[0])
        elif type == 'TCP':
            self.packet = packet_bin
        else:
            print('Unexcept Type')
            self.parent.Enable()
            self.Close()

        self.MainPanel = wx.Panel(parent=self)
        self.TextCtrl = wx.TextCtrl(parent=self.MainPanel, style=wx.TE_MULTILINE | wx.TE_CHARWRAP | wx.TE_READONLY,
                                    size=(575, 300), pos=(5, 5))
        points = self.TextCtrl.GetFont().GetPointSize()
        self.TextCtrl.SetFont(wx.Font(pointSize=points + 1, family=wx.MODERN, style=wx.NORMAL, weight=wx.NORMAL))
        if type != 'TCP':
            self.TextCtrl.SetValue(self.packet.show(True))
        else:
            try:
                self.TextCtrl.SetValue(self.packet.decode('utf-8'))
            except:
                self.TextCtrl.SetValue(str(self.packet))

        self.SaveButton = wx.Button(parent=self.MainPanel, label='保存',
                                    size=(80, 40), pos=(110, 310))
        self.SaveButton.Bind(wx.EVT_BUTTON, self.OnSave)
        if type != 'TCP':
            self.SaveButton.Disable()

        self.CloseButton = wx.Button(parent=self.MainPanel, label='关闭',
                                    size=(80, 40), pos=(410, 310))
        self.CloseButton.Bind(wx.EVT_BUTTON, self.OnButtonClose)

        self.Bind(wx.EVT_CLOSE, self.OnClose)
        self.CenterOnParent()

    def OnClose(self, evt):
        # print('close')
        self.parent.Enable()
        # self.Close()
        evt.Skip()

    def OnButtonClose(self, evt):
        # print('close')
        self.parent.Enable()
        self.Close()
        # evt.Skip()

    def OnSave(self, evt):
        file_wildcard = "Pcap files(*.pcap)|*.pcap"
        dlg = wx.FileDialog(self,
                            "Save as ...",
                            os.getcwd(),
                            style=wx.FD_SAVE | wx.FD_OVERWRITE_PROMPT,
                            wildcard=file_wildcard)
        dlg.SetFilename(time.strftime('%Y-%m-%d-%H-%M-%S', time.localtime(time.time())))
        if dlg.ShowModal() == wx.ID_OK:
            path = dlg.GetPath()
            pass


class TestFrame(wx.Frame):
    def __init__(self, parent):
        wx.Frame.__init__(self, parent, -1, "Simple Grid Demo", size=(816, 500))
        # self.grid = ReasseblyWindow(self, 'IP', b'E\x00\x000\x17\x8d\x00\x00\x80\x11\x02\x96\xc0\xa8\x00i:0%Yz\xca\xe6\xba\x00\x1c5\x14A\x00\x82Y9N\x9d\x8b\x00\x00\x00\x00\x00\x10\x00\x00\xae>\x00\x00')
        self.grid = ReasseblyWindow(self, 'TCP', b'\xbe\nz\xca*\x00\xd7*\x8f<+\x91\x80\x18\x1c\x843#\x00\x00\x01\x01\x08\n\x00\xf7\x0e1.\xe4\xcd\xda\x13BitTorrent protocol\x00\x00\x00\x00\x00\x10\x00\x05\x87}-A\xd3gj\xe1\xd7\xceU\x05\xa4n\xdc\x9e/\xf5>D-TR2840-vkzsgc0pa9yw')
        self.grid.Show()

if __name__ == '__main__':
    app = wx.App(False)
    frame = TestFrame(None)
    frame.Show(True)
    app.MainLoop()