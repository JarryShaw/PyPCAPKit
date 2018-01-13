import wx.grid
import wx
from scapy.all import *
import scapy
import datetime

dictionary = {0:'HOPOPT', 1:'ICMP', 2:'IGMP',
              3:'GGP', 4:'IPv4', 5:'ST', 6:'TCP',
              7:'CBT', 8:'EGP', 9:'IGP', 10:'BBN-RCC-MON',
              11:'NVP-II', 12:'PUP', 13:'ARGUS (deprecated)',
              14:'EMCON', 15:'XNET', 16:'CHAOS', 17:'UDP',
              18:'MUX', 19:'DCN-MEAS', 20:'HMP', 21:'PRM',
              22:'XNS-IDP', 23:'TRUNK-1', 24:'TRUNK-2',
              25:'LEAF-1', 26:'LEAF-2', 27:'RDP', 28:'IRTP',
              29:'ISO-TP4', 30:'NETBLT', 31:'MFE-NSP',
              32:'MERIT-INP', 33:'DCCP', 34:'3PC', 35:'IDPR',
              36:'XTP', 37:'DDP', 38:'IDPR-CMTP', 39:'TP++',
              40:'IL', 41:'IPv6', 42:'SDRP', 43:'IPv6-Route',
              44:'IPv6-Frag', 45:'IDRP', 46:'RSVP', 47:'GRE',
              48:'DSR', 49:'BNA', 50:'ESP', 51:'AH', 52:'I-NLSP',
              53:'SWIPE (deprecated)', 54:'NARP', 55:'MOBILE',
              56:'TLSP', 57:'SKIP', 58:'IPv6-ICMP', 59:'IPv6-NoNxt',
              60:'IPv6-Opts', 61:'', 62:'CFTP', 63:'', 64:'SAT-EXPAK',
              65:'KRYPTOLAN', 66:'RVD', 67:'IPPC', 68:'',
              69:'SAT-MON', 70:'VISA', 71:'IPCV', 72:'CPNX',
              73:'CPHB', 74:'WSN', 75:'PVP', 76:'BR-SAT-MON',
              77:'SUN-ND', 78:'WB-MON', 79:'WB-EXPAK', 80:'ISO-IP',
              81:'VMTP', 82:'SECURE-VMTP', 83:'VINES', 84:'TTP',
              85:'NSFNET-IGP', 86:'DGP', 87:'TCF',
              88:'EIGRP', 89:'OSPFIGP', 90:'Sprite-RPC', 91:'LARP',
              92:'MTP', 93:'AX.25', 94:'IPIP', 95:'MICP (deprecated)',
              96:'SCC-SP', 97:'ETHERIP', 98:'ENCAP', 99:'', 100:'GMTP',
              101:'IFMP', 102:'PNNI', 103:'PIM', 104:'ARIS', 105:'SCPS',
              106:'QNX', 107:'A/N', 108:'IPComp', 109:'SNP', 110:'Compaq-Peer',
              111:'IPX-in-IP', 112:'VRRP', 113:'PGM', 114:'',
              115:'L2TP', 116:'DDX', 117:'IATP', 118:'STP', 119:'SRP',
              120:'UTI', 121:'SMP', 122:'SM (deprecated)', 123:'PTP',
              124:'ISIS over IPv4', 125:'FIRE', 126:'CRTP', 127:'CRUDP',
              128:'SSCOPMCE', 129:'IPLT', 130:'SPS', 131:'PIPE',
              132:'SCTP', 133:'FC', 134:'RSVP-E2E-IGNORE', 135:'Mobility Header',
              136:'UDPLite', 137:'MPLS-in-IP', 138:'manet', 139:'HIP',
              140:'Shim6', 141:'WESP', 142:'ROHC', 253:'', 254:'', 255:'Reserved'}

class PacketGrid(wx.grid.Grid):
    def __init__(self, parent=None, id=-1):
        wx.grid.Grid.__init__(self, parent, id)
        self.CreateGrid(0, 7)
        # self.CreateGrid(7, 6)
        #隐藏行标识
        self.HideRowLabels()
        #禁止改变行高
        self.DisableDragRowSize()
        #只读？
        self.EnableEditing(False)
        #隐藏一开始的默认选定，第二个有效，第一个不知道有什么用
        self.SetCellHighlightPenWidth(0)
        self.SetCellHighlightROPenWidth(0)

        self.Packets = scapy.plist.PacketList()

        self.SearchPackets = scapy.plist.PacketList()

        #设置列名
        self.SetColLabelValue(0, u"编号")
        self.SetColLabelValue(1, u"时间")
        self.SetColLabelValue(2, u"源地址")
        self.SetColLabelValue(3, u"目的地址")
        self.SetColLabelValue(4, u"协议类型")
        self.SetColLabelValue(5, u"长度")
        self.SetColLabelValue(6, u"信息")
        self.SetColLabelAlignment(wx.ALIGN_CENTER, wx.ALIGN_CENTER)

        #设置列宽
        self.SetColSize(col=0, width=50)
        self.SetColSize(col=1, width=140)
        self.SetColSize(col=2, width=100)
        self.SetColSize(col=3, width=100)
        self.SetColSize(col=4, width=80)
        self.SetColSize(col=5, width=80)
        self.SetColSize(col=6, width=250)

        self.SetGridLineColour(wx.Colour(0, 0, 0))

        #设置各种包显示的颜色
        self.attrIP4 = wx.grid.GridCellAttr()
        self.attrIP4.SetBackgroundColour(wx.Colour(205, 231, 197))
        self.attrIP4.SetReadOnly(True)
        self.attrIP6 = wx.grid.GridCellAttr()
        self.attrIP6.SetBackgroundColour(wx.Colour(180, 239, 226))
        self.attrIP6.SetReadOnly(True)
        self.attrTCP = wx.grid.GridCellAttr()
        self.attrTCP.SetBackgroundColour(wx.Colour(219, 194, 237))
        self.attrTCP.SetReadOnly(True)
        self.attrUDP = wx.grid.GridCellAttr()
        self.attrUDP.SetBackgroundColour(wx.Colour(247, 177, 208))
        self.attrUDP.SetReadOnly(True)
        self.attrICMP = wx.grid.GridCellAttr()
        self.attrICMP.SetBackgroundColour(wx.Colour(255, 226, 154))
        self.attrICMP.SetReadOnly(True)
        self.attrIGMP = wx.grid.GridCellAttr()
        self.attrIGMP.SetBackgroundColour(wx.Colour(255, 182, 157))
        self.attrIGMP.SetReadOnly(True)
        self.attrARP = wx.grid.GridCellAttr()
        self.attrARP.SetBackgroundColour(wx.Colour(200, 200, 200))
        self.attrARP.SetReadOnly(True)

        # #测试颜色
        # self.SetRowAttr(0, attrIP4)
        # self.SetRowAttr(1, attrIP6)
        # self.SetRowAttr(2, attrTCP)
        # self.SetRowAttr(3, attrUDP)
        # self.SetRowAttr(4, attrICMP)
        # self.SetRowAttr(5, attrIGMP)
        # self.SetRowAttr(6, attrARP)

    def Load(self, path):
        if self.GetNumberRows() != 0:
            self.Packets = scapy.plist.PacketList()
            self.DeleteRows(0, self.GetNumberRows())
        Packets = sniff(offline=path)
        for packet in Packets:
            self.AddPacket(packet)

    def Search(self, search):
        self.SearchPackets = scapy.plist.PacketList()
        for packet in self.Packets:
            if search['protocol']['enable']:
                pro = []
                tmp = packet
                while tmp.payload:
                    pro.append(tmp.name)
                    tmp = tmp.payload
                pro.append(tmp.name)
                if search['protocol']['value'] not in pro:
                    continue
            if search['srcaddress']['enable']:
                try:
                    src = packet.payload.src
                except:
                    continue
                if search['srcaddress']['value'] != src:
                    continue
            if search['dstaddress']['enable']:
                try:
                    dst = packet.payload.dst
                except:
                    continue
                if search['dstaddress']['value'] != dst:
                    continue
            if search['srcport']['enable']:
                try:
                    sport = str(packet.sport)
                except:
                    continue
                if search['srcport']['value'] != sport:
                    continue
            if search['dstport']['enable']:
                try:
                    dport = str(packet.dport)
                except:
                    continue
                if search['dstport']['value'] != dport:
                    continue
            if search['key']['enable']:
                tmp = str(packet)
                if search['key']['value'] not in tmp:
                    continue
            self.SearchPackets.append(packet)
        self.SearchPackets.summary()
        self.ReFresh(self.SearchPackets)

    def ReFresh(self, packets):
        if self.GetNumberRows() != 0:
            self.DeleteRows(0, self.GetNumberRows())
        for packet in packets:
            self.DisplayPacket(packet)

    def Redisplay(self):
        self.ReFresh(self.Packets)

    def DisplayPacket(self, packet):
        TimeStamp = packet.time
        DateArray = datetime.datetime.utcfromtimestamp(TimeStamp)
        PacketTime = DateArray.strftime("%Y-%m-%d %H:%M:%S")
        PacketType = packet.type
        summary = packet.summary()
        info1 = summary.split(' / ')
        info = sorted(info1, key=lambda x:len(x), reverse=True)[0]
        if PacketType == 2054:
            Type = 'ARP'
            source = packet.payload.psrc
            destination = packet.payload.pdst
        else:
            Type = packet.payload.payload.name
            source = packet.payload.src
            destination = packet.payload.dst
        index = [self.GetNumberRows()+1, PacketTime, source, destination, Type, len(packet), info]
        self.AppendRows()
        for i in range(7):
            self.SetCellValue(index[0]-1, i, str(index[i]))
        if index[-3] == 'TCP':
            self.SetRowAttr(index[0]-1, self.attrTCP.Clone())
        elif index[-3] == 'UDP':
            self.SetRowAttr(index[0]-1, self.attrUDP.Clone())
        elif index[-3] == 'ICMP':
            self.SetRowAttr(index[0]-1, self.attrICMP.Clone())
        elif index[-3] == 'IGMP':
            self.SetRowAttr(index[0]-1, self.attrIGMP.Clone())
        elif index[-3] == 'IPv4':
            self.SetRowAttr(index[0]-1, self.attrIP4.Clone())
        elif '6' in index[-3]:
            self.SetRowAttr(index[0]-1, self.attrIP6.Clone())
        elif index[-3] == 'ARP':
            self.SetRowAttr(index[0]-1, self.attrARP.Clone())

    def AddPacket(self, packet):
        print(packet.summary())
        self.Packets.append(packet)
        self.DisplayPacket(packet)

    def Resize(self, size):
        self.SetColSize(col=0, width=size/16)
        self.SetColSize(col=1, width=size*7/40)
        self.SetColSize(col=2, width=size/8)
        self.SetColSize(col=3, width=size/8)
        self.SetColSize(col=4, width=size/10)
        self.SetColSize(col=5, width=size/10)
        self.SetColSize(col=6, width=size*5/16)

class TestFrame(wx.Frame):
    def __init__(self, parent):
        wx.Frame.__init__(self, parent, -1, "Simple Grid Demo", size=(816, 500))
        self.grid = PacketGrid(self)

if __name__ == '__main__':
    app = wx.App(False)
    frame = TestFrame(None)
    frame.Show(True)
    app.MainLoop()
