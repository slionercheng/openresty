#!/bin/bash

# 设置颜色输出
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# 设置项目根目录
PROJECT_ROOT=$(pwd)
BUILD_DIR="$PROJECT_ROOT/build_local"
INSTALL_DIR="$PROJECT_ROOT/install_local"

# 创建构建和安装目录
mkdir -p "$BUILD_DIR"
mkdir -p "$INSTALL_DIR"

# 检查是否需要执行 configure
NEED_CONFIGURE=0
if [ ! -f "$BUILD_DIR/Makefile" ]; then
    echo -e "${YELLOW}未找到 Makefile，需要执行 configure...${NC}"
    NEED_CONFIGURE=1
else
    # 检查 bundle/ngx_http_anp_module 目录下是否有新文件
    if [ -n "$(find bundle/ngx_http_anp_module -newer $BUILD_DIR/Makefile 2>/dev/null)" ]; then
        echo -e "${YELLOW}检测到 ngx_http_anp_module 目录下有新文件或修改，需要重新执行 configure...${NC}"
        NEED_CONFIGURE=1
    fi
    
    # 检查 configure 脚本是否比 Makefile 新
    if [ "configure" -nt "$BUILD_DIR/Makefile" ]; then
        echo -e "${YELLOW}检测到 configure 脚本有更新，需要重新执行 configure...${NC}"
        NEED_CONFIGURE=1
    fi
fi

# 如果需要，执行 configure
if [ $NEED_CONFIGURE -eq 1 ]; then
    echo -e "${GREEN}执行 configure...${NC}"
    
    # 备份旧的构建目录
    if [ -d "$BUILD_DIR" ]; then
        mv "$BUILD_DIR" "${BUILD_DIR}_backup_$(date +%Y%m%d%H%M%S)"
        mkdir -p "$BUILD_DIR"
    fi
    
    # 执行 configure，将构建产物放在项目目录中
    ./configure \
        --prefix="$INSTALL_DIR" \
        --add-module=bundle/ngx_http_anp_module \
        --with-debug \
        --with-cc-opt="-O0 -g" \
        --build="$BUILD_DIR"
    
    if [ $? -ne 0 ]; then
        echo -e "${RED}configure 失败！${NC}"
        exit 1
    fi
else
    echo -e "${GREEN}无需执行 configure，直接编译...${NC}"
fi

# 编译
echo -e "${GREEN}开始编译...${NC}"
cd nginx-1.27.1  # 切换到nginx目录
make

if [ $? -ne 0 ]; then
    echo -e "${RED}编译失败！${NC}"
    exit 1
fi

# 安装
echo -e "${GREEN}开始安装...${NC}"
make install

if [ $? -ne 0 ]; then
    echo -e "${RED}安装失败！${NC}"
    exit 1
fi

cd ..  # 返回原目录

echo -e "${GREEN}编译和安装完成！${NC}"
echo -e "${GREEN}安装目录: $INSTALL_DIR${NC}"
echo -e "${YELLOW}要运行 OpenResty，请使用以下命令:${NC}"
echo -e "${YELLOW}$INSTALL_DIR/bin/openresty -p $PROJECT_ROOT -c anp-test.conf${NC}"

# 创建一个便捷的运行脚本
cat > "$PROJECT_ROOT/run.sh" << EOF
#!/bin/bash
$INSTALL_DIR/bin/openresty -p $PROJECT_ROOT -c anp-test.conf "\$@"
EOF

chmod +x "$PROJECT_ROOT/run.sh"

echo -e "${GREEN}已创建运行脚本: $PROJECT_ROOT/run.sh${NC}"
echo -e "${YELLOW}使用方法: ./run.sh${NC}"
echo -e "${YELLOW}停止服务: ./run.sh -s stop${NC}"
