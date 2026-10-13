/* ScreenWings x86 read-only API observer. Run inside a disposable Windows VM.
 * No bypass, output alteration, or change to application state.
 */
'use strict';
const stamp=()=>new Date().toISOString();
const log=(event,fields)=>send(Object.assign({at:stamp(),event,pid:Process.id},fields||{}));
const hooked=new Set();
function txt(p,wide){
  try {if(p.isNull()||p.compare(ptr(0x10000))<0)return String(p);
       return (wide?p.readUtf16String():p.readCString()).slice(0,240);}
  catch(_){return '<unreadable>';}
}
function hx(p){return '0x'+(p.toUInt32()>>>0).toString(16);}
function hook(module,name,callbacks){
  let m,addr;
  try{m=Process.getModuleByName(module);addr=m.getExportByName(name);}catch(_){return;}
  if(hooked.has(String(addr)))return;
  hooked.add(String(addr));Interceptor.attach(addr,callbacks);
  log('hook-installed',{module,symbol:name,address:String(addr)});
}
function install(){
  for(const n of ['SetWindowDisplayAffinity','GetWindowDisplayAffinity']){
    hook('user32.dll',n,{
      onEnter(a){this.hwnd=String(a[0]);this.arg2=n==='SetWindowDisplayAffinity'?hx(a[1]):String(a[1]);
        this.stack=Thread.backtrace(this.context,Backtracer.ACCURATE).slice(0,8).map(DebugSymbol.fromAddress).map(String);},
      onLeave(r){log(n,{hwnd:this.hwnd,affinity_or_pointer:this.arg2,success:r.toInt32()!==0,stack:this.stack});}
    });
  }
  for(const wide of [false,true]){
    const name='CreateWindowEx'+(wide?'W':'A');
    hook('user32.dll',name,{
      onEnter(a){this.style=hx(a[0]);this.cls=txt(a[1],wide);this.title=txt(a[2],wide);
        this.x=a[4].toInt32();this.y=a[5].toInt32();this.w=a[6].toInt32();this.h=a[7].toInt32();},
      onLeave(r){log(name,{hwnd:String(r),exstyle:this.style,class:this.cls,title:this.title,
        rect:[this.x,this.y,this.w,this.h]});}
    });
  }
  hook('user32.dll','SetWindowPos',{
    onEnter(a){this.d={hwnd:String(a[0]),insert_after:String(a[1]),x:a[2].toInt32(),y:a[3].toInt32(),
      width:a[4].toInt32(),height:a[5].toInt32(),flags:hx(a[6])};},
    onLeave(r){log('SetWindowPos',Object.assign(this.d,{success:r.toInt32()!==0}));}
  });
  for(const mod of ['kernel32.dll','kernelbase.dll']){
    hook(mod,'GetProcAddress',{
      onEnter(a){this.handle=String(a[0]);this.api=txt(a[1],false);},
      onLeave(r){if(/WindowDisplayAffinity|CreateWindow|SetWindowPos|BitBlt|PrintWindow|Dwm/i.test(this.api))
        log('GetProcAddress',{provider:mod,module_handle:this.handle,api:this.api,result:String(r)});}
    });
  }
}
install();
if(typeof Process.attachModuleObserver==='function')
  Process.attachModuleObserver({onAdded:()=>install()});
log('observer-ready',{arch:Process.arch});
