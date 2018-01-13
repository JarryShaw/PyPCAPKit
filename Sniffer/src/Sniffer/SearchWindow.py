# coding=utf-8
import wx


class SearchWindow(wx.Frame):
    def __init__(self, Parent, Title):
        wx.Frame.__init__(self, parent=Parent, title=Title, size=(600, 400),
                          style=wx.CAPTION | wx.CLOSE_BOX | wx.FRAME_FLOAT_ON_PARENT)
        self.CentreOnParent()
        self.parent = Parent
        self._InitUI()

        self.Bind(wx.EVT_CLOSE, self.OnClose)

    def _InitUI(self):
        top_splitter = wx.SplitterWindow(self)

        panel0 = wx.Panel(top_splitter, -1)
        panel1 = wx.Panel(top_splitter, -1)

        top_splitter.SetSashGravity(0.85)
        top_splitter.SplitHorizontally(panel1, panel0)

        self.CheckPro = wx.CheckBox(parent=panel1, label=u'选择协议', pos=(20, 25))
        self.ListPro = wx.ComboBox(parent=panel1, pos=(100, 20), size=(100, 35),
                                   choices=['None', 'Ethernet', 'IP', 'IPv6',
                                            'ARP', 'RARP', 'TCP', 'UDP', 'ICMP', 'IGMP'],
                                   style=wx.CB_READONLY)
        self.ListPro.SetSelection(0)
        self.CheckPro.Bind(wx.EVT_CHECKBOX, self.OnSelectPro)
        self.ListPro.Disable()

        self.CheckSrcAddr = wx.CheckBox(parent=panel1, label=u'源地址设置', pos=(20, 45))
        self.SrcAddr = wx.TextCtrl(parent=panel1, pos=(20, 70), size=(260, 28))
        self.CheckSrcAddr.Bind(wx.EVT_CHECKBOX, self.OnSelectSrcAddr)
        self.SrcAddr.Disable()

        self.CheckDstAddr = wx.CheckBox(parent=panel1, label=u'目的地址设置', pos=(300, 45))
        self.DstAddr = wx.TextCtrl(parent=panel1, pos=(300, 70), size=(260, 28))
        self.CheckDstAddr.Bind(wx.EVT_CHECKBOX, self.OnSelectDstAddr)
        self.DstAddr.Disable()

        self.CheckSrcPort = wx.CheckBox(parent=panel1, label=u'源端口设置', pos=(20, 125))
        self.SrcPort = wx.TextCtrl(parent=panel1, pos=(20, 150), size=(260, 28))
        self.CheckSrcPort.Bind(wx.EVT_CHECKBOX, self.OnSelectSrcPort)
        self.SrcPort.Disable()

        self.CheckDstPort = wx.CheckBox(parent=panel1, label=u'目的端口设置', pos=(300, 125))
        self.DstPort = wx.TextCtrl(parent=panel1, pos=(300, 150), size=(260, 28))
        self.CheckDstPort.Bind(wx.EVT_CHECKBOX, self.OnSelectDstPort)
        self.DstPort.Disable()

        self.CheckKey = wx.CheckBox(parent=panel1, label=u'关键字设置', pos=(20, 225))
        self.Key = wx.TextCtrl(parent=panel1, pos=(20, 255), size=(540, 28))
        self.Key.Disable()
        self.CheckKey.Bind(wx.EVT_CHECKBOX, self.OnSelectKey)

        Button1 = wx.Button(panel0, label=u'确定', size=(80, 40), pos=(50, 10))
        Button1.Bind(wx.EVT_BUTTON, self.OnConfirm)
        Button2 = wx.Button(panel0, label=u'取消', size=(80, 40), pos=(450, 10))
        Button2.Bind(wx.EVT_BUTTON, self.OnClose)
        Button3 = wx.Button(panel0, label=u'重置', size=(80, 40), pos=(183, 10))
        Button3.Bind(wx.EVT_BUTTON, self.OnClear)
        Button4 = wx.Button(panel0, label=u'帮助', size=(80, 40), pos=(317, 10))
        Button4.Bind(wx.EVT_BUTTON, self.OnHelp)

    def OnSelectKey(self, event):
        sel = event.GetSelection()
        if sel:
            self.Key.Enable()
        else:
            self.Key.Disable()

    def OnSelectPro(self, event):
        sel = event.GetSelection()
        if sel:
            self.ListPro.Enable()
        else:
            self.ListPro.Disable()

    def OnSelectSrcAddr(self, event):
        sel = event.GetSelection()
        if sel:
            self.SrcAddr.Enable()
        else:
            self.SrcAddr.Disable()

    def OnSelectDstAddr(self, event):
        sel = event.GetSelection()
        if sel:
            self.DstAddr.Enable()
        else:
            self.DstAddr.Disable()

    def OnSelectSrcPort(self, event):
        sel = event.GetSelection()
        if sel:
            self.SrcPort.Enable()
        else:
            self.SrcPort.Disable()

    def OnSelectDstPort(self, event):
        sel = event.GetSelection()
        if sel:
            self.DstPort.Enable()
        else:
            self.DstPort.Disable()

    def OnHelp(self, event):
        pass

    def OnClear(self, event):
        self.ListPro.SetSelection(0)
        self.SrcAddr.SetValue('')
        self.DstAddr.SetValue('')
        self.SrcPort.SetValue('')
        self.DstPort.SetValue('')
        self.Key.SetValue('')
        self.parent.Grid.Redisplay()
        self.parent.ifsearch = 0

    def OnClose(self, event):
        self.parent.Grid.Redisplay()
        self.Hide()
        self.parent.ifsearch = 0

    def OnConfirm(self, event):
        self.parent.ifsearch = 1
        search = {'protocol':{'enable':0,
                              'value':''},
                  'srcaddress':{'enable':0,
                             'value':''},
                  'dstaddress':{'enable':0,
                             'value':''},
                  'srcport':{'enable':0,
                          'value':''},
                  'dstport':{'enable':0,
                          'value':''},
                  'key':{'enable':0,
                         'value':''}}
        if self.CheckPro.GetValue():
            search['protocol']['enable'] = 1
            if self.ListPro.GetStringSelection() == 'None':
                dlg = wx.MessageDialog(None, u'未选择协议类型', u'提示')
                dlg.ShowModal()
                dlg.Destroy()
                return
            search['protocol']['value'] = self.ListPro.GetStringSelection()
        else:
            search['protocol']['enable'] = 0
            search['protocol']['value'] = ''
        if self.CheckSrcAddr.GetValue():
            search['srcaddress']['enable'] = 1
            if self.SrcAddr.GetValue() == '':
                dlg = wx.MessageDialog(None, u'未填写源地址', u'提示')
                dlg.ShowModal()
                dlg.Destroy()
                return
            search['srcaddress']['value'] = self.SrcAddr.GetValue()
        else:
            search['srcaddress']['enable'] = 0
            search['srcaddress']['value'] = ''
        if self.CheckDstAddr.GetValue():
            search['dstaddress']['enable'] = 1
            if self.DstAddr.GetValue() == '':
                dlg = wx.MessageDialog(None, u'未填写目的地址', u'提示')
                dlg.ShowModal()
                dlg.Destroy()
                return
            search['dstaddress']['value'] = self.DstAddr.GetValue()
        else:
            search['dstaddress']['enable'] = 0
            search['dstaddress']['value'] = ''
        if self.CheckSrcPort.GetValue():
            search['srcport']['enable'] = 1
            if self.SrcPort.GetValue() == '':
                dlg = wx.MessageDialog(None, u'未填写源端口', u'提示')
                dlg.ShowModal()
                dlg.Destroy()
                return
            search['srcport']['value'] = self.SrcPort.GetValue()
        else:
            search['srcport']['enable'] = 0
            search['srcport']['value'] = ''
        if self.CheckDstPort.GetValue():
            search['dstport']['enable'] = 1
            if self.DstPort.GetValue() == '':
                dlg = wx.MessageDialog(None, u'未填写目的端口', u'提示')
                dlg.ShowModal()
                dlg.Destroy()
                return
            search['dstport']['value'] = self.DstPort.GetValue()
        else:
            search['dstport']['enable'] = 0
            search['dstport']['value'] = ''
        if self.CheckKey.GetValue():
            search['key']['enable'] = 1
            if self.Key.GetValue() == '':
                dlg = wx.MessageDialog(None, u'未填写关键字', u'提示')
                dlg.ShowModal()
                dlg.Destroy()
                return
            search['key']['value'] = self.Key.GetValue()
        else:
            search['key']['enable'] = 0
            search['key']['value'] = ''
        print(search)
        self.parent.Grid.Search(search)

class TestFrame(wx.Frame):
    def __init__(self, parent):
        wx.Frame.__init__(self, parent, -1, "Simple Grid Demo", size=(816, 500))
        self.grid = SearchWindow(self, 'eee')
        self.grid.Show()

if __name__ == '__main__':
    app = wx.App(False)
    frame = TestFrame(None)
    frame.Show(True)
    app.MainLoop()