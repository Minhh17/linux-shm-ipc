// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2022 MediaTek Inc.
 * Author: Garmin Chang <garmin.chang@mediatek.com>
 */

#include <dt-bindings/clock/mediatek,mt8188-clk.h>
#include <dt-bindings/reset/mt8188-resets.h>
#include <linux/clk-provider.h>
#include <linux/platform_device.h>

#include "clk-gate.h"
#include "clk-mtk.h"

static const struct mtk_gate_regs infra_ao0_cg_regs = {
	.set_ofs = 0x80,
	.clr_ofs = 0x84,
	.sta_ofs = 0x90,
};

static const struct mtk_gate_regs infra_ao1_cg_regs = {
	.set_ofs = 0x88,
	.clr_ofs = 0x8c,
	.sta_ofs = 0x94,
};

static const struct mtk_gate_regs infra_ao2_cg_regs = {
	.set_ofs = 0xa4,
	.clr_ofs = 0xa8,
	.sta_ofs = 0xac,
};

static const struct mtk_gate_regs infra_ao3_cg_regs = {
	.set_ofs = 0xc0,
	.clr_ofs = 0xc4,
	.sta_ofs = 0xc8,
};

static const struct mtk_gate_regs infra_ao4_cg_regs = {
	.set_ofs = 0xe0,
	.clr_ofs = 0xe4,
	.sta_ofs = 0xe8,
};

#define GATE_INFRA_AO0_FLAGS(_id, _name, _parent, _shift, _flag)                \
	GATE_MTK_FLAGS(_id, _name, _parent, &infra_ao0_cg_regs, _shift, \
		&mtk_clk_gate_ops_setclr, _flag)

#define GATE_INFRA_AO0(_id, _name, _parent, _shift)	\
	GATE_INFRA_AO0_FLAGS(_id, _name, _parent, _shift, 0)

#define GATE_INFRA_AO1_FLAGS(_id, _name, _parent, _shift, _flag)		\
	GATE_MTK_FLAGS(_id, _name, _parent, &infra_ao1_cg_regs, _shift,	\
		&mtk_clk_gate_ops_setclr, _flag)

#define GATE_INFRA_AO1(_id, _name, _parent, _shift)	\
	GATE_INFRA_AO1_FLAGS(_id, _name, _parent, _shift, 0)

#define GATE_INFRA_AO2(_id, _name, _parent, _shift)			\
	GATE_MTK(_id, _name, _parent, &infra_ao2_cg_regs, _shift, &mtk_clk_gate_ops_setclr)

#define GATE_INFRA_AO2_FLAGS(_id, _name, _parent, _shift, _flag)		\
	GATE_MTK_FLAGS(_id, _name, _parent, &infra_ao2_cg_regs, _shift,	\
		&mtk_clk_gate_ops_setclr, _flag)

#define GATE_INFRA_AO3_FLAGS(_id, _name, _parent, _shift, _flag)		\
	GATE_MTK_FLAGS(_id, _name, _parent, &infra_ao3_cg_regs, _shift,	\
		&mtk_clk_gate_ops_setclr, _flag)

#define GATE_INFRA_AO3(_id, _name, _parent, _shift)	\
	GATE_INFRA_AO3_FLAGS(_id, _name, _parent, _shift, 0)

#define GATE_INFRA_AO4_FLAGS(_id, _name, _parent, _shift, _flag)		\
	GATE_MTK_FLAGS(_id, _name, _parent, &infra_ao4_cg_regs, _shift,	\
		&mtk_clk_gate_ops_setclr, _flag)

#define GATE_INFRA_AO4(_id, _name, _parent, _shift)	\
	GATE_INFRA_AO4_FLAGS(_id, _name, _parent, _shift, 0)

static const struct mtk_gate infra_ao_clks[] = {
	/* INFRA_AO0 */
	GATE_INFRA_AO0(CLK_INFRA_AO_PMIC_TMR, "infra_ao_pmic_tmr", "top_pwrap_ulposc", 0),
	GATE_INFRA_AO0(CLK_INFRA_AO_PMIC_AP, "infra_ao_pmic_ap", "top_pwrap_ulposc", 1),
	GATE_INFRA_AO0(CLK_INFRA_AO_PMIC_MD, "infra_ao_pmic_md", "top_pwrap_ulposc", 2),
	GATE_INFRA_AO0(CLK_INFRA_AO_PMIC_CONN, "infra_ao_pmic_conn", "top_pwrap_ulposc", 3),
	/* infra_ao_sej is main clock is for secure engine with JTAG support */
	GATE_INFRA_AO0_FLAGS(CLK_INFRA_AO_SEJ, "infra_ao_sej", "top_axi", 5, CLK_IS_CRITICAL),
	GATE_INFRA_AO0(CLK_INFRA_AO_APXGPT, "infra_ao_apxgpt", "top_axi", 6),
	GATE_INFRA_AO0(CLK_INFRA_AO_GCE, "infra_ao_gce", "top_axi", 8),
	GATE_INFRA_AO0(CLK_INFRA_AO_GCE2, "infra_ao_gce2", "top_axi", 9),
	GATE_INFRA_AO0(CLK_INFRA_AO_THERM, "infra_ao_therm", "top_axi", 10),
	GATE_INFRA_AO0(CLK_INFRA_AO_PWM_HCLK, "infra_ao_pwm_h", "top_axi", 15),
	GATE_INFRA_AO0(CLK_INFRA_AO_PWM1, "infra_ao_pwm1", "top_pwm", 16),
	GATE_INFRA_AO0(CLK_INFRA_AO_PWM2, "infra_ao_pwm2", "top_pwm", 17),
	GATE_INFRA_AO0(CLK_INFRA_AO_PWM3, "infra_ao_pwm3", "top_pwm", 18),
	GATE_INFRA_AO0(CLK_INFRA_AO_PWM4, "infra_ao_pwm4", "top_pwm", 19),
	GATE_INFRA_AO0(CLK_INFRA_AO_PWM, "infra_ao_pwm", "top_pwm", 21),
	GATE_INFRA_AO0(CLK_INFRA_AO_UART0, "infra_ao_uart0", "top_uart", 22),
	GATE_INFRA_AO0(CLK_INFRA_AO_UART1, "infra_ao_uart1", "top_uart", 23),
	GATE_INFRA_AO0(CLK_INFRA_AO_UART2, "infra_ao_uart2", "top_uart", 24),
	GATE_INFRA_AO0(CLK_INFRA_AO_UART3, "infra_ao_uart3", "top_uart", 25),
	GATE_INFRA_AO0(CLK_INFRA_AO_UART4, "infra_ao_uart4", "top_uart", 26),
	GATE_INFRA_AO0(CLK_INFRA_AO_GCE_26M, "infra_ao_gce_26m", "clk26m", 27),
	GATE_INFRA_AO0(CLK_INFRA_AO_CQ_DMA_FPC, "infra_ao_dma", "pad_fpc_ck", 28),
	GATE_INFRA_AO0(CLK_INFRA_AO_UART5, "infra_ao_uart5", "top_uart", 29),
	/* INFRA_AO1 */
	GATE_INFRA_AO1(CLK_INFRA_AO_HDMI_26M, "infra_ao_hdmi_26m", "clk26m", 0),
	GATE_INFRA_AO1(CLK_INFRA_AO_SPI0, "infra_ao_spi0", "top_spi", 1),
	GATE_INFRA_AO1(CLK_INFRA_AO_MSDC0, "infra_ao_msdc0", "top_msdc5hclk", 2),
	GATE_INFRA_AO1(CLK_INFRA_AO_MSDC1, "infra_ao_msdc1", "top_axi", 4),
	GATE_INFRA_AO1(CLK_INFRA_AO_MSDC2, "infra_ao_msdc2", "top_axi", 5),
	GATE_INFRA_AO1(CLK_INFRA_AO_MSDC0_SRC, "infra_ao_msdc0_clk", "top_msdc50_0", 6),
	/* infra_ao_dvfsrc is for internal DVFS usage, should not be handled by Linux. */
	GATE_INFRA_AO1_FLAGS(CLK_INFRA_AO_DVFSRC, "infra_ao_dvfsrc",
			     "clk26m", 7, CLK_IS_CRITICAL),
	GATE_INFRA_AO1(CLK_INFRA_AO_TRNG, "infra_ao_trng", "top_axi", 9),
	GATE_INFRA_AO1(CLK_INFRA_AO_AUXADC, "infra_ao_auxadc", "clk26m", 10),
	GATE_INFRA_AO1(CLK_INFRA_AO_CPUM, "infra_ao_cpum", "top_axi", 11),
	GATE_INFRA_AO1(CLK_INFRA_AO_HDMI_32K, "infra_ao_hdmi_32k", "clk32k", 12),
	GATE_INFRA_AO1(CLK_INFRA_AO_CEC_66M_HCLK, "infra_ao_cec_66m_hclk", "top_axi", 13),
	GATE_INFRA_AO1(CLK_INFRA_AO_PCIE_TL_26M, "infra_ao_pcie_tl_26m", "clk26m", 15),
	GATE_INFRA_AO1(CLK_INFRA_AO_MSDC1_SRC, "infra_ao_msdc1_clk", "top_msdc30_1", 16),
	GATE_INFRA_AO1(CLK_INFRA_AO_CEC_66M_BCLK, "infra_ao_cec_66m_bclk", "top_axi", 17),
	GATE_INFRA_AO1(CLK_INFRA_AO_PCIE_TL_96M, "infra_ao_pcie_tl_96m", "top_tl", 18),
	/* infra_ao_dapc is for device access permission control module */
	GATE_INFRA_AO1_FLAGS(CLK_INFRA_AO_DEVICE_APC, "infra_ao_dapc",
			     "top_axi", 20, CLK_IS_CRITICAL),
	GATE_INFRA_AO1(CLK_INFRA_AO_ECC_66M_HCLK, "infra_ao_ecc_66m_hclk", "top_axi", 23),
	GATE_INFRA_AO1(CLK_INFRA_AO_DEBUGSYS, "infra_ao_debugsys", "top_axi", 24),
	GATE_INFRA_AO1(CLK_INFRA_AO_AUDIO, "infra_ao_audio", "top_axi", 25),
	GATE_INFRA_AO1(CLK_INFRA_AO_PCIE_TL_32K, "infra_ao_pcie_tl_32k", "clk32k", 26),
	GATE_INFRA_AO1(CLK_INFRA_AO_DBG_TRACE, "infra_ao_dbg_trace", "top_axi", 29),
	GATE_INFRA_AO1(CLK_INFRA_AO_DRAMC_F26M, "infra_ao_dramc26", "clk26m", 31),
	/* INFRA_AO2 */
	GATE_INFRA_AO2(CLK_INFRA_AO_IRTX, "infra_ao_irtx", "top_axi", 0),
	GATE_INFRA_AO2(CLK_INFRA_AO_DISP_PWM, "infra_ao_disp_pwm", "top_disp_pwm0", 2),
	GATE_INFRA_AO2(CLK_INFRA_AO_CLDMA_BCLK, "infra_ao_cldmabclk", "top_axi", 3),
	GATE_INFRA_AO2(CLK_INFRA_AO_AUDIO_26M_BCLK, "infra_ao_audio26m", "clk26m", 4),
	GATE_INFRA_AO2(CLK_INFRA_AO_SPI1, "infra_ao_spi1", "top_spi", 6),
	GATE_INFRA_AO2(CLK_INFRA_AO_SPI2, "infra_ao_spi2", "top_spi", 9),
	GATE_INFRA_AO2(CLK_INFRA_AO_SPI3, "infra_ao_spi3", "top_spi", 10),
	GATE_INFRA_AO2_FLAGS(CLK_INFRA_AO_FSSPM, "infra_ao_fsspm",
			     "top_sspm", 15, CLK_IS_CRITICAL),
	GATE_INFRA_AO2_FLAGS(CLK_INFRA_AO_SSPM_BUS_HCLK, "infra_ao_sspm_hclk",
			     "top_axi", 17, CLK_IS_CRITICAL),
	GATE_INFRA_AO2(CLK_INFRA_AO_APDMA_BCLK, "infra_ao_apdma_bclk", "top_axi", 18),
	GATE_INFRA_AO2(CLK_INFRA_AO_SPI4, "infra_ao_spi4", "top_spi", 25),
	GATE_INFRA_AO2(CLK_INFRA_AO_SPI5, "infra_ao_spi5", "top_spi", 26),
	GATE_INFRA_AO2(CLK_INFRA_AO_CQ_DMA, "infra_ao_cq_dma", "top_axi", 27),
	/* INFRA_AO3 */
	GATE_INFRA_AO3(CLK_INFRA_AO_MSDC0_SELF, "infra_ao_msdc0sf", "top_msdc50_0", 0),
	GATE_INFRA_AO3(CLK_INFRA_AO_MSDC1_SELF, "infra_ao_msdc1sf", "top_msdc50_0", 1),
	GATE_INFRA_AO3(CLK_INFRA_AO_MSDC2_SELF, "infra_ao_msdc2sf", "top_msdc50_0", 2),
	GATE_INFRA_AO3(CLK_INFRA_AO_I2S_DMA, "infra_ao_i2s_dma", "top_axi", 5),
	GATE_INFRA_AO3(CLK_INFRA_AO_AP_MSDC0, "infra_ao_ap_msdc0", "top_msdc50_0", 7),
	GATE_INFRA_AO3(CLK_INFRA_AO_MD_MSDC0, "infra_ao_md_msdc0", "top_msdc50_0", 8),
	GATE_INFRA_AO3(CLK_INFRA_AO_MSDC30_2, "infra_ao_msdc30_2", "top_msdc30_2", 9),
	GATE_INFRA_AO3(CLK_INFRA_AO_GCPU, "infra_ao_gcpu", "top_gcpu", 10),
	GATE_INFRA_AO3(CLK_INFRA_AO_PCIE_PERI_26M, "infra_ao_pcie_peri_26m", "clk26m", 15),
	GATE_INFRA_AO3(CLK_INFRA_AO_GCPU_66M_BCLK, "infra_ao_gcpu_66m_bclk", "top_axi", 16),
	GATE_INFRA_AO3(CLK_INFRA_AO_GCPU_133M_BCLK, "infra_ao_gcpu_133m_bclk", "top_axi", 17),
	GATE_INFRA_AO3(CLK_INFRA_AO_DISP_PWM1, "infra_ao_disp_pwm1", "top_disp_pwm1", 20),
	GATE_INFRA_AO3(CLK_INFRA_AO_FBIST2FPC, "infra_ao_fbist2fpc", "top_msdc50_0", 24),
	/* infra_ao_dapc_sync is for device access permission control module */
	GATE_INFRA_AO3_FLAGS(CLK_INFRA_AO_DEVICE_APC_SYNC, "infra_ao_dapc_sync",
			     "top_axi", 25, CLK_IS_CRITICAL),
	GATE_INFRA_AO3(CLK_INFRA_AO_PCIE_P1_PERI_26M, "infra_ao_pcie_p1_peri_26m", "clk26m", 26),
	/* INFRA_AO4 */
	/* infra_ao_133m_mclk_set/infra_ao_66m_mclk_set are main clocks of peripheral */
	GATE_INFRA_AO4_FLAGS(CLK_INFRA_AO_133M_MCLK_CK, "infra_ao_133m_mclk_set",
			     "top_axi", 0, CLK_IS_CRITICAL),
	GATE_INFRA_AO4_FLAGS(CLK_INFRA_AO_66M_MCLK_CK, "infra_ao_66m_mclk_set",
			     "top_axi", 1, CLK_IS_CRITICAL),
	GATE_INFRA_AO4(CLK_INFRA_AO_PCIE_PL_P_250M_P0, "infra_ao_pcie_pl_p_250m_p0",
		       "pextp_pipe", 7),
	GATE_INFRA_AO4(CLK_INFRA_AO_RG_AES_MSDCFDE_CK_0P,
		       "infra_ao_aes_msdcfde_0p", "top_aes_msdcfde", 18),
};

static u16 infra_ao_rst_ofs[] = {
	INFRA_RST0_SET_OFFSET,
	INFRA_RST1_SET_OFFSET,
	INFRA_RST2_SET_OFFSET,
	INFRA_RST3_SET_OFFSET,
	INFRA_RST4_SET_OFFSET,
};

static u16 infra_ao_idx_map[] = {
	[MT8188_INFRA_RST1_THERMAL_MCU_RST] = 1 * RST_NR_PER_BANK + 2,
	[MT8188_INFRA_RST1_THERMAL_CTRL_RST] = 1 * RST_NR_PER_BANK + 4,
	[MT8188_INFRA_RST3_PTP_CTRL_RST] = 3 * RST_NR_PER_BANK + 5,
};

static const struct mtk_clk_rst_desc infra_ao_rst_desc = {
	.version = MTK_RST_SET_CLR,
	.rst_bank_ofs = infra_ao_rst_ofs,
	.rst_bank_nr = ARRAY_SIZE(infra_ao_rst_ofs),
	.rst_idx_map = infra_ao_idx_map,
	.rst_idx_map_nr = ARRAY_SIZE(infra_ao_idx_map),
};

static const struct mtk_clk_desc infra_ao_desc = {
	.clks = infra_ao_clks,
	.num_clks = ARRAY_SIZE(infra_ao_clks),
	.rst_desc = &infra_ao_rst_desc,
};

static const struct of_device_id of_match_clk_mt8188_infra_ao[] = {
	{ .compatible = "mediatek,mt8188-infracfg-ao", .data = &infra_ao_desc },
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, of_match_clk_mt8188_infra_ao);

static struct platform_driver clk_mt8188_infra_ao_drv = {
	.probe = mtk_clk_simple_probe,
	.remove_new = mtk_clk_simple_remove,
	.driver = {
		.name = "clk-mt8188-infra_ao",
		.of_match_table = of_match_clk_mt8188_infra_ao,
	},
};
module_platform_driver(clk_mt8188_infra_ao_drv);

MODULE_DESCRIPTION("MediaTek MT8188 infracfg clocks driver");
MODULE_LICENSE("GPL");
