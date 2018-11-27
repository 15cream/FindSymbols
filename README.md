# FindSymbols


查看MachO文件动态链接的符号，根据其bind信息，查找在二进制中可能的引用。
基于工具：objdump、IDA

主要文件：
binary.py：基于objdump获得动态链接的库与符号。
msybol.py：基于IDA获得符号可能的使用方法。根据bind所处segment会有不同的引用类型，比如作为protocol，作为category，作为classref等等，每一类都有不同的检测方案。（待完善中）

工具的本意，是想知道一个二进制链接了哪些库和符号，而这些符号在代码中是怎么被使用的。
对于想要检测的符号，可以使用MachOA的工具再进一步进行分析。

代码：
macho = MachO('path_of_MachO_binary')
macho.parse_bind_info()  # 解析bind信息，包括lazy_bind

\# 我想看_OBJC_CLASS_$_MKMapItem的引用情况, 名称要完整，可以看下macho.bind_indexed_by_symbol的数据结构
\# 虽然这里的格式十分冗余
s = MSymbol('_OBJC_CLASS_$_MKMapItem', macho.bind_indexed_by_symbol['_OBJC_CLASS_$_MKMapItem'])  
s.find_usage()

for f in s.xrefs:
    fn = idc.GetFunctionName(f)
    print hex(fn), fn

结果示例：（MapKit framework 的 MKMapItem 类，作为classref时在某二进制中被以下方法引用）
_OBJC_CLASS_$_MKMapItem __objc_classrefs
0x100125220L -[DetailViewController setRootViewController:]
0x1001e0464L -[MessageViewController DirectionsToHereButton:]
0x1001b9ae4L -[BOMDetailViewController directionToHere:]
0x10013df6cL -[WaitingSplashScreenViewController viewDidLoad]
0x1000edc3cL -[ItemDetailViewController viewDirectionsToHereForItem:]
0x1000b454cL -[EBAdsDetailViewController directionToHere:]
0x100015a70L -[AppDelegate closeWaitingSplashView:]
0x1000b4874L -[EBAdsDetailViewController directionFromHere:]
0x1001e06b8L -[MessageViewController DirectionsFromHereButton:]
0x1001ba094L -[BOMDetailViewController directionFromHere:]
0x1000ee27cL -[ItemDetailViewController viewDirectionsFromHereForItem:]

粒度：只考虑了直接引用，例如直接被方法体引用，或者当被某subroutine引用时，会往上追直到以[receiver selector]形式出现。
会考虑循环，或者顶层的情况。MSymbol的processed里面是中间subroutine。
暂时没做数据流分析，例如该类的对象作为参数或作为返回值的情况，也暂时未做block。
