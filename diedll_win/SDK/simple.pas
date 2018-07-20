unit Unit1;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes, Vcl.Graphics,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls, Vcl.Buttons;

type
  TFormMain = class(TForm)
    BitBtnScan: TBitBtn;
    MemoResult: TMemo;
    procedure BitBtnScanClick(Sender: TObject);
  private
    { Private declarations }
  public
    { Public declarations }
  end;

var
  FormMain: TFormMain;
  Buffer: array [0..1023] of AnsiChar;
  sResult: String;

implementation
 function DIE_scanA(pszFileName: PAnsiChar; pszOutBuffer: PAnsiChar; nOutBufferSize: Cardinal; nFlags: Cardinal): Integer; stdcall; external 'diedll.dll' name '_DIE_scanA@16';
{$R *.dfm}

procedure TFormMain.BitBtnScanClick(Sender: TObject);
begin
  DIE_scanA(PAnsiChar('C:\WINDOWS\notepad.exe'), @Buffer[Low(Buffer)], SizeOf(Buffer), 0);
  MemoResult.Text:=string(Buffer);
end;

end.
