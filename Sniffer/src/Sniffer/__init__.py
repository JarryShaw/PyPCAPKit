# coding=utf-8
# import wx
from scapy.all import rdpcap, wrpcap
from GetIFace import *
import _thread
from Sniffer.PacketGrid import *
import time
from Sniffer.FilterWindow import *
from Sniffer.SearchWindow import *
from Sniffer.ReassemblyWindow import *
from .reassembly import IPv4_Reassembly, IPv6_Reassembly,TCP_Reassembly


class SnifferFrame(wx.Frame):
    def __init__(self, Parent=None, ID=-1, Title=None, Pos=(100, 100), Size=(816, 600)):
        wx.Frame.__init__(self, parent=Parent, id=ID, title=Title, pos=Pos, size=Size)

        #get iface
        self.iface = None
        self.ifacelist = GetIface()

        #create filter
        self.filter = ''
        self.FilterWindow = FilterWindow(self, u'过滤设置')

        #create Reassembly
        self.IPv4 = IPv4_Reassembly()
        self.IPv6 = IPv6_Reassembly()
        self.TCP = TCP_Reassembly()

        #create search
        # self.search = {'protocol':{'enable':0,
        #                            'value':''},
        #                'address':{'enable':0,
        #                           'direction':'',
        #                           'type':'',
        #                           'value':''},
        #                'port':{'enable':0,
        #                        'direction':'',
        #                        'type':'',
        #                        'value':''},
        #                'key':{'enable':0,
        #                       'value':''}}
        self.ifsearch = 0
        self.SearchWindow = SearchWindow(self, u'查找')

        #self.status is an int for saving sniffer's status
        #0-stop
        #1-sniffing
        self.status = 0

        #init UI
        self._InitUI()

    def _InitUI(self):
        # #create timer
        # self.Timer = wx.Timer(self)
        # self._SetTimer()
        # self.Bind(wx.EVT_TIMER, self.OnTimer, self.Timer)

        #create menubar
        self.menuBar = wx.MenuBar()
        self._AppendMenu()
        self.SetMenuBar(self.menuBar)
        self.Bind(wx.EVT_MENU, self.BarHandler, self.menuBar)

        #create statusbar
        self.statusBar = self.CreateStatusBar()
        self._SetStatusBar()
        self.SetStatusBar(self.statusBar)

        #create toolBar
        self.toolBar = self.CreateToolBar(wx.TB_HORIZONTAL | wx.TB_TEXT)
        self._AppendTool()
        self.SetToolBar(self.toolBar)
        self.Bind(wx.EVT_TOOL, self.BarHandler, self.toolBar)

        # init Panel
        self.OnInitPanel()
        self.Bind(wx.EVT_SIZE, self.Resize)

    def Resize(self, evt):
        size = (evt.GetSize()[0] - 16, evt.GetSize()[1] - 144)
        self.top_splitter.SetSize(size)
        self.Grid.Resize(size[0])

    def DestroyPanel(self):
        self.StatusString.Destroy()
        self.Grid.Destroy()
        self.LabelString.Destroy()
        self.Detail.Destroy()

    def OnInitPanel(self):
        self.top_splitter = wx.SplitterWindow(self, -1, style=wx.SP_3D)
        self.sec_splitter = wx.SplitterWindow(self.top_splitter, -1, style=wx.SP_3D)

        self.GridPanel = wx.Panel(self.top_splitter, -1)
        self.DetailPanel = wx.Panel(self.sec_splitter, -1)
        self.DumpPanel = wx.Panel(self.sec_splitter, -1)

        self.sec_splitter.SplitVertically(self.DetailPanel, self.DumpPanel)
        self.sec_splitter.SetSashGravity(0.5)
        self.top_splitter.SplitHorizontally(self.GridPanel, self.sec_splitter)
        self.top_splitter.SetSashGravity(0.5)

        GridSizer = wx.BoxSizer(wx.VERTICAL)
        self.StatusString = wx.StaticText(self.GridPanel, -1, u'抓包停止', style=wx.ALIGN_CENTER)
        self.StatusString.CenterOnParent(wx.HORIZONTAL)
        GridSizer.Add(self.StatusString, proportion=0, flag=wx.EXPAND | wx.ALL, border=5)
        self.Grid = PacketGrid(self.GridPanel, 0)
        GridSizer.Add(self.Grid, proportion=2, flag=wx.EXPAND | wx.ALL, border=0)
        self.GridPanel.SetSizer(GridSizer)

        DetailSizer = wx.BoxSizer(wx.VERTICAL)
        self.LabelString = wx.StaticText(self.DetailPanel, -1, u'详细信息', style=wx.ALIGN_CENTER)
        DetailSizer.Add(self.LabelString, proportion=0, flag=wx.EXPAND | wx.ALL, border=5)
        self.Detail = wx.TextCtrl(self.DetailPanel, style=wx.TE_MULTILINE | wx.TE_CHARWRAP | wx.TE_READONLY, size=(1000, 1000))
        points = self.Detail.GetFont().GetPointSize()
        self.Detail.SetFont(wx.Font(pointSize=points + 1, family=wx.MODERN, style=wx.NORMAL, weight=wx.NORMAL))
        DetailSizer.Add(self.Detail, proportion=1, flag=wx.EXPAND | wx.ALL, border=5)
        self.DetailPanel.SetSizer(DetailSizer)

        DumpSizer = wx.BoxSizer(wx.VERTICAL)
        # self.DumpLabel = wx.RadioBox(parent=self.DumpPanel, label=u'选择报文重组方式', choices=[u'IPv4报文', u'IPv6报文', u'TCP报文'])
        # self.DumpLabel.Bind(wx.EVT_RADIOBOX, self.OnRadio)
        self.DumpLabel = wx.StaticText(parent=self.DumpPanel, label=u'报文', style=wx.ALIGN_CENTER)
        DumpSizer.Add(self.DumpLabel, proportion=0, flag=wx.EXPAND | wx.ALL, border=5)
        self.Dump = wx.TextCtrl(self.DumpPanel, style=wx.TE_MULTILINE | wx.TE_READONLY | wx.TE_DONTWRAP, size=(1000, 1000))
        points = self.Dump.GetFont().GetPointSize()
        self.Dump.SetFont(wx.Font(pointSize=points + 1, family=wx.MODERN, style=wx.NORMAL, weight=wx.NORMAL))
        DumpSizer.Add(self.Dump, proportion=1, flag=wx.EXPAND | wx.ALL, border=5)
        self.DumpPanel.SetSizer(DumpSizer)

        #左单击
        self.Bind(wx.grid.EVT_GRID_CELL_LEFT_CLICK, self.OnCellLeftClick)

    def OnCellLeftClick(self, evt):
        self.Grid.SelectRow(evt.GetRow())
        row = self.Grid.GetSelectedRows()[0]
        if self.ifsearch:
            tmp = self.Grid.SearchPackets[row]
        else:
            tmp = self.Grid.Packets[row]
        detail = tmp.show2(True)
        self.Detail.SetValue(detail)
        dump = hexdump(tmp, True)
        self.Dump.SetValue(dump)

    def _AppendMenu(self):
        MenuFile = wx.Menu()
        MenuFile.Append(101, u'关于(&A)', u'关于本程序')
        MenuFile.Append(102, u'储存(&S)', u'储存为pcap文件')
        MenuFile.Append(103, u'打开本地文件(&O)', u'选择本地pcap文件')
        MenuFile.AppendSeparator()
        MenuFile.Append(104, u'退出(&E)', u'退出')

        MenuFilter = wx.Menu()
        MenuFilter.Append(201, u'过滤选项(&F)', u'过滤流量包')
        MenuFilter.Append(202, u'查找(&F)', u'查找流量包')

        choicelist = []
        for i in range(len(self.ifacelist)):
            choicelist.append(self.ifacelist[i])
        dlg = wx.SingleChoiceDialog(self, u'选择监听的网卡', u'网卡选择', choicelist, style=wx.OK|wx.CENTRE)
        dlg.ShowModal()
        self.iface = dlg.GetStringSelection()
        dlg.Destroy()

        MenuIface = wx.Menu()
        for i in range(len(self.ifacelist)):
            MenuIface.Append(300+i, self.ifacelist[i], kind=wx.ITEM_RADIO)
            if self.iface == self.ifacelist[i]:
                MenuIface.Check(300+i, True)

        self.menuBar.Append(MenuFile, u'文件')
        self.menuBar.Append(MenuFilter, u'过滤与查找')
        self.menuBar.Append(MenuIface, u'网卡选择')

    def BarHandler(self, event):
        id = event.GetId()
        if id == 1:
            self.OnFilter()
        elif id == 2:
            self.OnStart()
        elif id == 3:
            self.OnStop()
        elif id == 4:
            self.OnSave()
        elif id == 5:
            self.OnAbout()
        elif id == 6:
            self.OnExit()
        elif id == 7:
            self.OnOpen()
        elif id == 8:
            self.OnSearch()
        elif id == 9:
            self.IPReassembly()
        elif id == 10:
            self.OnExport()
        elif id == 11:
            self.TCPReassembly()
        elif id == 101:
            self.OnAbout()
        elif id == 102:
            self.OnSave()
        elif id == 103:
            self.OnOpen()
        elif id == 104:
            self.OnExit()
        elif id == 201:
            self.OnFilter()
        elif id == 202:
            self.OnSearch()
        elif id >= 300:
            self.iface = self.ifacelist[id-300]['Description']

    def IPReassembly(self):
        try:
            num = self.Grid.GetSelectedRows()[0]
        except:
            dlg = wx.MessageDialog(None, u'未选择包', u'提示')
            dlg.ShowModal()
            dlg.Destroy()
            return
        if self.ifsearch:
            packet = self.Grid.SearchPackets[num]
            for i in range(len(self.Grid.Packets)):
                if packet == self.Grid.Packets[i]:
                    num = i
                    continue
        else:
            packet = self.Grid.Packets[num]
        pro = []
        tmp = packet
        while tmp.payload:
            pro.append(tmp.name)
            tmp = tmp.payload
        pro.append(tmp.name)
        if 'IP' in pro:
            if 'MF' not in packet[IP].flags.flagrepr():
                dlg = wx.MessageDialog(None, u'此报文未分片。', u'提示')
                dlg.ShowModal()
                dlg.Destroy()
                return
            n = self.IPv4.index(num)
            if n is None:
                dlg = wx.MessageDialog(None, u'未接收到全部报文，无法进行报文重组。', u'提示')
                dlg.ShowModal()
                dlg.Destroy()
                return
            window = ReassemblyWindow(parent=self, type='IP', packet_bin=self.IPv4.datagram[n].payload)
        elif 'IPv6' in pro:
            if IPv6ExtHdrFragment not in packet:
                dlg = wx.MessageDialog(None, u'此报文未分片。', u'提示')
                dlg.ShowModal()
                dlg.Destroy()
                return
            n = self.IPv6.index(num)
            if n is None:
                dlg = wx.MessageDialog(None, u'未接收到全部报文，无法进行报文重组。', u'提示')
                dlg.ShowModal()
                dlg.Destroy()
                return
            window = ReassemblyWindow(parent=self, type='IPv6', packet_bin=self.IPv6.datagram[n].payload)
        else:
            dlg = wx.MessageDialog(None, u'这不是一个IPv4或IPv6报文', u'提示')
            dlg.ShowModal()
            dlg.Destroy()
            return
        self.Disable()
        window.Show()

    def TCPReassembly(self):
        try:
            num = self.Grid.GetSelectedRows()[0]
        except:
            dlg = wx.MessageDialog(None, u'未选择包', u'提示')
            dlg.ShowModal()
            dlg.Destroy()
            return
        if self.ifsearch:
            packet = self.Grid.SearchPackets[num]
            for i in range(len(self.Grid.Packets)):
                if packet == self.Grid.Packets[i]:
                    num = i
                    continue
        else:
            packet = self.Grid.Packets[num]
        try:
            packet[TCP]
        except:
            dlg = wx.MessageDialog(None, u'这不是一个TCP报文', u'提示')
            dlg.ShowModal()
            dlg.Destroy()
            return
        if not packet[TCP].payload:
            dlg = wx.MessageDialog(None, u'这个TCP报文不携带数据', u'提示')
            dlg.ShowModal()
            dlg.Destroy()
            return
        n = self.TCP.index(num)
        if n is None:
            dlg = wx.MessageDialog(None, u'未接收到全部报文，无法进行报文重组。', u'提示')
            dlg.ShowModal()
            dlg.Destroy()
            return
        self.Disable()
        window = ReassemblyWindow(parent=self, type='TCP', packet_bin=self.TCP.datagram[n].payload)
        window.Show()

    def OnExit(self):
        if self.status == 0:
            dlg = wx.MessageDialog(self, u'您确定要退出吗？', u'提示', wx.YES_NO | wx.NO_DEFAULT | wx.STAY_ON_TOP)
            result = dlg.ShowModal()
            dlg.Destroy()
            if result == wx.ID_YES:
                self.Close()
        else:
            dlg = wx.MessageDialog(self, u'是否确定停止捕获，并不保存直接退出？', u'提示', wx.YES_NO | wx.NO_DEFAULT | wx.STAY_ON_TOP)
            result = dlg.ShowModal()
            dlg.Destroy()
            if result == wx.ID_YES:
                self.status = 0
                self.Close()

    def OnAbout(self):
        dlg = wx.MessageDialog(self, u'关于', u'关于', wx.OK)
        dlg.ShowModal()
        dlg.Destroy()

    def OnSave(self):
        file_wildcard = "Pcap files(*.pcap)|*.pcap"
        dlg = wx.FileDialog(self,
                            "Save as ...",
                            os.getcwd(),
                            style=wx.FD_SAVE | wx.FD_OVERWRITE_PROMPT,
                            wildcard=file_wildcard)
        dlg.SetFilename(time.strftime('%Y-%m-%d-%H-%M-%S', time.localtime(time.time())))
        if dlg.ShowModal() == wx.ID_OK:
            path = dlg.GetPath()
            wrpcap(path, self.Grid.Packets)

    def OnOpen(self):
        file_wildcard = "Pcap files(*.pcap)|*.pcap"
        dlg = wx.FileDialog(self, "Open file...",
                            os.getcwd(),
                            style=wx.FD_OPEN,
                            wildcard=file_wildcard)
        if dlg.ShowModal() == wx.ID_OK:
            path = dlg.GetPath()
            self.Grid.Load(path)
        num = 0
        for packet in self.Grid.Packets:
            pro = []
            tmp = packet
            while tmp.payload:
                pro.append(tmp.name)
                tmp = tmp.payload
            pro.append(tmp.name)
            if 'IP' in pro:
                self.OnIPv4Reassembly(packet, num - 1)
            if 'IPv6' in pro:
                self.OnIPv6Reassembly(packet, num - 1)
            if 'TCP' in pro:
                self.OnTCPReassembly(packet, num - 1)
            num += 1

    def OnExport(self):
        file_wildcard = "Text files(*.txt)|*.txt"
        dlg = wx.FileDialog(self, "Save as...",
                            os.getcwd(),
                            style=wx.FD_SAVE | wx.FD_OVERWRITE_PROMPT,
                            wildcard=file_wildcard)
        dlg.SetFilename(time.strftime('%Y-%m-%d-%H-%M-%S', time.localtime(time.time())))
        if dlg.ShowModal() == wx.ID_OK:
            path = dlg.GetPath()
            rows = self.Grid.GetSelectedRows()
            if len(rows) == 0:
                dlg = wx.MessageDialog(None, u'未选择packet', u'提示')
                dlg.ShowModal()
                dlg.Destroy()
                return
            file = open(path, 'w')
            for row in rows:
                file.write(self.Grid.Packets[row].show2(True))
                file.write('\n')


    def OnFilter(self):
        self.Disable()
        self.FilterWindow.Show(True)

    def OnSearch(self):
        self.SearchWindow.Show(True)

    def OnIPv4Reassembly(self, packet, num):
        packet_dic = {}
        p = packet.payload
        packet_dic['num'] = num
        packet_dic['bufid'] = (p.src, p.dst, p.id, p.proto)
        packet_dic['fo'] = p.frag
        packet_dic['ihl'] = p.ihl*4
        if 'DF' in p.flags.flagrepr():
            return
        if 'MF' in p.flags.flagrepr():
            packet_dic['mf'] = 1
        else:
            packet_dic['mf'] = 0
        packet_dic['tl'] = p.len
        packet_dic['header'] = bytearray(p.raw_packet_cache)
        packet_dic['payload'] = bytearray(p.payload.original)
        # print(packet_dic)
        self.IPv4(packet_dic)

    def OnIPv6Reassembly(self, packet, num):
        pro = []
        tmp = packet
        while tmp.payload:
            pro.append(tmp.name)
            tmp = tmp.payload
        pro.append(tmp.name)
        if 'IPv6 Extension Header - Fragmentation header' not in pro:
            return
        packet_dic = {}
        packet_dic['num'] = num
        p = packet.payload
        f = packet[IPv6ExtHdrFragment]
        packet_dic['bufid'] = (p.src, p.dst, p.fl, f.nh)
        packet_dic['fo'] = f.offset
        packet_dic['mf'] = f.m
        packet_dic['tl'] = p.plen + 40
        packet_dic['header'] = ''
        packet_dic['ihl'] = 0
        tmp = packet
        while tmp.payload.name != 'IPv6 Extension Header - Fragmentation header':
            packet_dic['header'] += bytearray(tmp.raw_packet_cache)
            packet_dic['ihl'] += len(tmp.raw_packet_cache)
        packet_dic['payload'] = bytearray(f.payload.original)
        # print(packet_dic)
        self.IPv6(packet_dic)

    def OnTCPReassembly(self, packet, num):
        packet_dic = {}
        packet_dic['num'] = num
        p = packet.payload
        t = p.payload
        packet_dic['bufid'] = (p.src, p.dst, t.sport, t.dport)
        packet_dic['ack'] = t.ack
        packet_dic['dsn'] = t.seq
        if 'S' in p.flags.flagrepr():
            packet_dic['syn'] = 1
        else:
            packet_dic['syn'] = 0
        if 'F' in p.flags.flagrepr():
            packet_dic['fin'] = 1
        else:
            packet_dic['fin'] = 0
        packet_dic['len'] = len(t.payload.original)
        packet_dic['first'] = t.seq
        packet_dic['last'] = packet_dic['len'] + packet_dic['first']
        packet_dic['header'] = bytearray(t.raw_packet_cache)
        packet_dic['payload'] = bytearray(t.payload.original)
        # print(packet_dic)
        self.TCP(packet_dic)

    # def _SetTimer(self):
    #     self.Timer.Start(10)
    #
    # def OnTimer(self, event):
    #     size = self.GetSize()[0]
    #     self.Grid.Resize(size)

    def _SetStatusBar(self):
        self.statusBar.SetFieldsCount(2)
        self.statusBar.SetStatusWidths([-1, -1])

    def _AppendTool(self):
        img1 = wx.Image('bitmaps/setting.png', wx.BITMAP_TYPE_PNG).Rescale(30, 30)
        img2 = wx.Image('bitmaps/start.png', wx.BITMAP_TYPE_PNG).Rescale(30, 30)
        img3 = wx.Image('bitmaps/stop.png', wx.BITMAP_TYPE_PNG).Rescale(30, 30)
        img4 = wx.Image('bitmaps/save.png', wx.BITMAP_TYPE_PNG).Rescale(30, 30)
        img5 = wx.Image('bitmaps/assistance.png', wx.BITMAP_TYPE_PNG).Rescale(30, 30)
        img6 = wx.Image('bitmaps/quit.png', wx.BITMAP_TYPE_PNG).Rescale(30, 30)
        img7 = wx.Image('bitmaps/open.png', wx.BITMAP_TYPE_PNG).Rescale(30, 30)
        img8 = wx.Image('bitmaps/search.png', wx.BITMAP_TYPE_PNG).Rescale(30, 30)
        img9 = wx.Image('bitmaps/combineIP.png', wx.BITMAP_TYPE_PNG).Rescale(30, 30)
        img10 = wx.Image('bitmaps/export.png', wx.BITMAP_TYPE_PNG).Rescale(30, 30)
        img11 = wx.Image('bitmaps/combineTCP.png', wx.BITMAP_TYPE_PNG).Rescale(30, 30)

        self.toolBar.AddTool(2, u"开始", img2.ConvertToBitmap(), u"开始抓包")
        self.toolBar.AddTool(3, u"停止", img3.ConvertToBitmap(), u"停止抓包")
        self.toolBar.AddTool(1, u"过滤", img1.ConvertToBitmap(), u"过滤设置")
        self.toolBar.AddSeparator()
        self.toolBar.AddTool(4, u"储存", img4.ConvertToBitmap(), u"储存监听结果")
        self.toolBar.AddTool(7, u"打开", img7.ConvertToBitmap(), u"打开pcap文件")
        self.toolBar.AddTool(10, u"导出", img10.ConvertToBitmap(), u"导出所选packet")
        self.toolBar.AddSeparator()
        self.toolBar.AddTool(8, u"查询", img8.ConvertToBitmap(), u"查询流量包")
        self.toolBar.AddTool(9, u"重组IP", img9.ConvertToBitmap(), u"IP报文重组")
        self.toolBar.AddTool(11, u"重组TCP", img11.ConvertToBitmap(), u"TCP报文重组")
        self.toolBar.AddSeparator()
        self.toolBar.AddTool(5, u"帮助", img5.ConvertToBitmap(), u"帮助")
        self.toolBar.AddTool(6, u"退出", img6.ConvertToBitmap(), u"退出程序")

        self.toolBar.EnableTool(3, False)

        self.toolBar.Realize()

    def OnStart(self):
        self.toolBar.EnableTool(2, False)
        self.toolBar.EnableTool(3, True)
        self.toolBar.EnableTool(1, False)
        self.toolBar.EnableTool(4, False)
        self.toolBar.EnableTool(7, False)
        self.toolBar.EnableTool(8, False)
        self.toolBar.EnableTool(9, False)
        self.StatusString.SetLabel(u'正在抓包……')
        self.StatusString.CenterOnParent(wx.HORIZONTAL)
        self.status = 1
        # self.sniffer = SnifferThread(self.iface, lambda x:x.summary, self.status==0)
        _thread.start_new_thread(self._sniffer, (self.iface, self._PackageOperat, self._IfRunning, self.filter))

    def _sniffer(self, iface, prn, s_filter, filter):
        sniff(iface=iface, prn=prn, stop_filter=s_filter, filter=filter)

    def _PackageOperat(self, packet):
        if self.status:
            self.Grid.AddPacket(packet)
            num = len(self.Grid.Packets)
            pro = []
            tmp = packet
            while tmp.payload:
                pro.append(tmp.name)
                tmp = tmp.payload
            pro.append(tmp.name)
            if 'IP' in pro:
                self.OnIPv4Reassembly(packet, num - 1)
            if 'IPv6' in pro:
                self.OnIPv6Reassembly(packet, num - 1)
            if 'TCP' in pro:
                self.OnTCPReassembly(packet, num - 1)

    def _IfRunning(self, packet):
        return self.status == 0

    def OnStop(self):
        self.toolBar.EnableTool(2, True)
        self.toolBar.EnableTool(3, False)
        self.toolBar.EnableTool(1, True)
        self.toolBar.EnableTool(4, True)
        self.toolBar.EnableTool(7, True)
        self.toolBar.EnableTool(8, True)
        self.toolBar.EnableTool(9, True)
        self.StatusString.SetLabel(u'抓包停止')
        self.StatusString.CenterOnParent(wx.HORIZONTAL)
        self.status = 0

class Sniffer(wx.App):
    def OnInit(self):
        self.myframe = SnifferFrame(Title='Sniffer')
        self.SetTopWindow(self.myframe)
        self.myframe.Centre()
        self.myframe.Show(True)
        return True

# class SnifferThread(Thread):
#     def __init__(self, Iface, Prn, StopFilter):
#         Thread.__init__(self)
#         self.sniffer = sniff(iface=Iface, prn=Prn, stop_filter=StopFilter)

if __name__ == '__main__':
    app = Sniffer()
    app.MainLoop()
