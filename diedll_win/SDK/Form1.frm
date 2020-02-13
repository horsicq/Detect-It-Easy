VERSION 5.00
Begin VB.Form Form1 
   Caption         =   "Form1"
   ClientHeight    =   4260
   ClientLeft      =   60
   ClientTop       =   345
   ClientWidth     =   9330
   LinkTopic       =   "Form1"
   ScaleHeight     =   4260
   ScaleWidth      =   9330
   StartUpPosition =   3  'Windows Default
   Begin VB.TextBox Text1 
      Height          =   3855
      Left            =   60
      MultiLine       =   -1  'True
      ScrollBars      =   3  'Both
      TabIndex        =   0
      Top             =   180
      Width           =   9015
   End
End
Attribute VB_Name = "Form1"
Attribute VB_GlobalNameSpace = False
Attribute VB_Creatable = False
Attribute VB_PredeclaredId = True
Attribute VB_Exposed = False

'vb6 sample
Const DIE_SHOWERRORS = &H1
Const DIE_SHOWOPTIONS = &H2
Const DIE_SHOWVERSION = &H4
Const DIE_SHOWENTROPY = &H8
Const DIE_SINGLELINEOUTPUT = &H10
Const DIE_SHOWFILEFORMATONCE = &H20

'http://ntinfo.biz/
Private Declare Function DiEScan Lib "diedll.dll" Alias "_DIE_scanA@16" (ByVal fileName As String, ByVal buf As String, ByVal bufSz As Long, ByVal flags As Long) As Long
Private Declare Function dieScanEx Lib "diedll.dll" Alias "_DIE_scanExA@20" (ByVal fileName As String, ByVal buf As String, ByVal bufSz As Long, ByVal flags As Long, ByVal dbPath As String) As Long
Private Declare Function dieVer Lib "diedll.dll" Alias "_DIE_versionA@0" () As Long

Private Declare Sub CopyMemory Lib "kernel32" Alias "RtlMoveMemory" (Destination As Any, Source As Any, ByVal Length As Long)
Private Declare Function lstrlenA Lib "kernel32" (ByVal lpString As Long) As Long

Function DieVersion() As String
    Dim addr As Long, leng As Long, b() As Byte
    addr = dieVer()
    If addr Then
        leng = lstrlenA(addr)
        If leng > 0 Then
            ReDim b(1 To leng)
            CopyMemory ByVal VarPtr(b(1)), ByVal addr, leng
            DieVersion = StrConv(b, vbUnicode, &H409)
        End If
    End If
End Function

Private Sub Form_Load()
    
    Dim v As Long
    Dim buf As String
    Dim flags As Long
    Dim a As Long
    
    flags = DIE_SHOWOPTIONS Or DIE_SHOWVERSION Or DIE_SHOWENTROPY Or DIE_SINGLELINEOUTPUT
    buf = String(1000, Chr(0))
    v = DiEScan("C:\windows\notepad.exe", buf, Len(buf), flags)
    'v = dieScanEx(fPath, buf, Len(buf), flags, App.path & "\die\db\")
    
    a = InStr(buf, Chr(0))
    If a > 0 Then buf = Left(buf, a - 1)
    buf = Replace(buf, vbLf, vbCrLf)
    Text1 = "DiE v" & DieVersion() & vbCrLf & buf
    
End Sub

