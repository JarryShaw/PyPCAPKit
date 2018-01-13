# coding=utf-8
import wx


class FilterWindow(wx.Frame):
    def __init__(self, Parent, Title):
        wx.Frame.__init__(self, parent=Parent, title=Title, size=(600, 400),
                          style=wx.CAPTION | wx.CLOSE_BOX | wx.FRAME_FLOAT_ON_PARENT)
        self.CentreOnParent()
        self.parent = Parent
        self._InitUI()

        self.Bind(wx.EVT_CLOSE, self.OnClose)

    def _InitUI(self):
        top_splitter = wx.SplitterWindow(self)
        sec_splitter = wx.SplitterWindow(top_splitter)

        panel0 = wx.Panel(top_splitter, -1)
        panel2 = wx.Panel(sec_splitter, -1)
        panel3 = wx.Panel(sec_splitter, -1)

        top_splitter.SetSashGravity(0.85)
        sec_splitter.SetSashGravity(0.24)
        top_splitter.SplitHorizontally(sec_splitter, panel0)
        sec_splitter.SplitHorizontally(panel2, panel3)

        self.Radio = wx.RadioBox(parent=panel2, label=u'选择使用方式', choices=[u'轻松使用', u'自定义过滤器'])
        self.Radio.CenterOnParent(wx.BOTH)
        RadioSizer = wx.BoxSizer()
        RadioSizer.Add(self.Radio, proportion=1, border=8, flag=wx.EXPAND | wx.ALL)
        panel2.SetSizer(RadioSizer)
        self.Radio.Bind(wx.EVT_RADIOBOX, self.OnRadioBox)

        self.TextCtrl = wx.TextCtrl(parent=panel3, style=wx.TE_MULTILINE | wx.TE_CHARWRAP,
                                    pos=(5, 0), size=(575, 220))
        self.TextCtrl.Hide()

        self.CheckPro = wx.CheckBox(parent=panel3, label=u'选择协议', pos=(20, 5))
        self.ListPro = wx.ComboBox(parent=panel3, pos=(100, 0), size=(100, 35),
                                   choices=['None', 'ether', 'fddi', 'tr', 'wlan', 'ip', 'ip6',
                                            'arp', 'rarp', 'decnet', 'tcp', 'udp', 'icmp', 'igmp'],
                                   style=wx.CB_READONLY)
        self.ListPro.SetSelection(0)
        self.CheckPro.Bind(wx.EVT_CHECKBOX, self.OnSelectPro)
        self.ListPro.Disable()

        self.CheckSrcAddr = wx.CheckBox(parent=panel3, label=u'源地址设置', pos=(20, 45))
        self.SrcAddr = wx.TextCtrl(parent=panel3, pos=(20, 70), size=(260, 28))
        self.CheckSrcAddr.Bind(wx.EVT_CHECKBOX, self.OnSelectSrcAddr)
        self.SrcAddr.Disable()

        self.CheckDstAddr = wx.CheckBox(parent=panel3, label=u'目的地址设置', pos=(300, 45))
        self.DstAddr = wx.TextCtrl(parent=panel3, pos=(300, 70), size=(260, 28))
        self.CheckDstAddr.Bind(wx.EVT_CHECKBOX, self.OnSelectDstAddr)
        self.DstAddr.Disable()

        self.CheckSrcPort = wx.CheckBox(parent=panel3, label=u'源端口设置', pos=(20, 125))
        self.SrcPort = wx.TextCtrl(parent=panel3, pos=(20, 150), size=(260, 28))
        self.CheckSrcPort.Bind(wx.EVT_CHECKBOX, self.OnSelectSrcPort)
        self.SrcPort.Disable()

        self.CheckDstPort = wx.CheckBox(parent=panel3, label=u'目的端口设置', pos=(300, 125))
        self.DstPort = wx.TextCtrl(parent=panel3, pos=(300, 150), size=(260, 28))
        self.CheckDstPort.Bind(wx.EVT_CHECKBOX, self.OnSelectDstPort)
        self.DstPort.Disable()


        Button1 = wx.Button(panel0, label=u'确定', size=(80, 40), pos=(50, 10))
        Button1.Bind(wx.EVT_BUTTON, self.OnConfirm)
        Button2 = wx.Button(panel0, label=u'取消', size=(80, 40), pos=(450, 10))
        Button2.Bind(wx.EVT_BUTTON, self.OnClose)
        Button3 = wx.Button(panel0, label=u'重置', size=(80, 40), pos=(183, 10))
        Button3.Bind(wx.EVT_BUTTON, self.OnClear)
        Button4 = wx.Button(panel0, label=u'帮助', size=(80, 40), pos=(317, 10))
        Button4.Bind(wx.EVT_BUTTON, self.OnHelp)

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
        self.TextCtrl.SetValue('')
        self.ListPro.SetSelection(0)
        self.SrcAddr.SetValue('')
        self.DstAddr.SetValue('')
        self.SrcPort.SetValue('')
        self.DstPort.SetValue('')

    def OnRadioBox(self, event):
        sel = event.GetSelection()
        if sel == 0:
            self.TextCtrl.Hide()
            self.CheckPro.Show()
            self.ListPro.Show()
            self.SrcAddr.Show()
            self.DstAddr.Show()
            self.SrcPort.Show()
            self.DstPort.Show()
        else:
            self.TextCtrl.Show()
            self.CheckPro.Hide()
            self.ListPro.Hide()
            self.SrcAddr.Hide()
            self.DstAddr.Hide()
            self.SrcPort.Hide()
            self.DstPort.Hide()

    def OnClose(self, event):
        self.parent.Enable(True)
        self.Hide()

    def OnConfirm(self, event):
        sel = self.Radio.GetSelection()
        if sel == 0:
            Filter = ''
            if self.CheckPro.GetValue():
                if self.ListPro.GetStringSelection() == 'None':
                    dlg = wx.MessageDialog(None, u'未选择协议类型', u'提示')
                    dlg.ShowModal()
                    dlg.Destroy()
                    return
                Filter += self.ListPro.GetStringSelection()
            if self.CheckSrcAddr.GetValue():
                if Filter != '':
                    Filter += ' and'
                if self.SrcAddr.GetValue() == '':
                    dlg = wx.MessageDialog(None, u'未填写源地址', u'提示')
                    dlg.ShowModal()
                    dlg.Destroy()
                    return
                Filter += ' src host '
                Filter += self.SrcAddr.GetValue()
            if self.CheckDstAddr.GetValue():
                if Filter != '':
                    Filter += ' and'
                if self.DstAddr.GetValue() == '':
                    dlg = wx.MessageDialog(None, u'未填写目的地址', u'提示')
                    dlg.ShowModal()
                    dlg.Destroy()
                    return
                Filter += ' dst host '
                Filter += self.DstAddr.GetValue()
            if self.CheckSrcPort.GetValue():
                if Filter != '':
                    Filter += ' and'
                if self.SrcPort.GetValue() == '':
                    dlg = wx.MessageDialog(None, u'未填写源端口', u'提示')
                    dlg.ShowModal()
                    dlg.Destroy()
                    return
                Filter += ' src port '
                Filter += self.SrcPort.GetValue()
            if self.CheckDstPort.GetValue():
                if Filter != '':
                    Filter += ' and'
                if self.DstPort.GetValue() == '':
                    dlg = wx.MessageDialog(None, u'未填写源端口', u'提示')
                    dlg.ShowModal()
                    dlg.Destroy()
                    return
                Filter += ' src port '
                Filter += self.DstPort.GetValue()
        else:
            Filter = self.TextCtrl.GetValue()
        print(Filter)
        self.parent.filter = Filter
        self.parent.Enable(True)
        self.Hide()

class TestFrame(wx.Frame):
    def __init__(self, parent):
        wx.Frame.__init__(self, parent, -1, "Simple Grid Demo", size=(816, 500))
        self.grid = FilterWindow(self, 'eee')
        self.grid.Show()

if __name__ == '__main__':
    app = wx.App(False)
    frame = TestFrame(None)
    frame.Show(True)
    app.MainLoop()