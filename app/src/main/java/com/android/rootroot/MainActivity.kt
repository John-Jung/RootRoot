package com.android.rootroot

import android.animation.ValueAnimator
import android.annotation.SuppressLint
import android.graphics.Color
import android.graphics.Typeface
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.view.animation.AccelerateDecelerateInterpolator
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import kotlin.concurrent.thread

class MainActivity : AppCompatActivity() {

    // ── Theme Colors ──────────────────────────────────────────
    private val colBg        = Color.parseColor("#0A0E14")
    private val colCard      = Color.parseColor("#131920")
    private val colBorder    = Color.parseColor("#1E2A35")
    private val colGreen     = Color.parseColor("#00FF41")
    private val colRed       = Color.parseColor("#FF3333")
    private val colAmber     = Color.parseColor("#FFB000")
    private val colCyan      = Color.parseColor("#00E5FF")
    private val colDim       = Color.parseColor("#4A5568")
    private val colText      = Color.parseColor("#CBD5E1")
    private val colBright    = Color.parseColor("#EEF2FF")
    private val colMuted     = Color.parseColor("#6B7B8D")

    private lateinit var cardsContainer: LinearLayout
    private lateinit var btnScanAll: Button
    private lateinit var txtSummary: TextView
    private lateinit var txtFooter: TextView
    private val handler = Handler(Looper.getMainLooper())

    private lateinit var rootingDetector: RootingDetector
    private val cardViews = mutableListOf<CardViewHolder>()

    // ── Data Model ────────────────────────────────────────────
    data class CheckItem(
        val name: String,
        val description: String,
        val method: String,       // JNI method type hint
        var result: Boolean? = null,
        var runTimeMs: Long = 0
    )

    data class CardData(
        val title: String,
        val icon: String,
        val subtitle: String,
        val checks: List<CheckItem>
    )

    class CardViewHolder(
        val root: LinearLayout,
        val headerLayout: LinearLayout,
        val titleView: TextView,
        val statusBadge: TextView,
        val arrowView: TextView,
        val bodyLayout: LinearLayout,
        val checkRows: MutableList<CheckRowHolder> = mutableListOf(),
        var expanded: Boolean = false
    )

    class CheckRowHolder(
        val row: LinearLayout,
        val indicator: TextView,
        val nameView: TextView,
        val resultView: TextView,
        val detailView: TextView
    )

    // ── Define All Checks ─────────────────────────────────────
    private fun buildCards(): List<CardData> = listOf(
        CardData(
            title = "JAVA LAYER",
            icon = "☕",
            subtitle = "PackageManager & File system checks",
            checks = listOf(
                CheckItem(
                    "Root Package Scan",
                    "Scans installed packages against ${Constants.knownRootAppsPackages.size} known root app signatures via PackageManager.getPackageInfo()",
                    "Java"
                ),
                CheckItem(
                    "SU Binary Search",
                    "Checks ${Constants.knownSuDirectories.size} directories for su/busybox/magisk binaries via java.io.File.exists()",
                    "Java"
                )
            )
        ),
        CardData(
            title = "NATIVE · STATIC",
            icon = "⚡",
            subtitle = "Exported JNI symbols — visible in symbol table",
            checks = listOf(
                CheckItem("Su Binary Check", "access(path, F_OK) on 7 known su paths", "Static JNI"),
                CheckItem("Magisk Mount", "Reads /proc/mounts for magisk mount points", "Static JNI"),
                CheckItem("Frida Process", "Scans /proc/*/cmdline for frida-server", "Static JNI"),
                CheckItem("Frida Library", "Reads /proc/self/maps for frida-agent/.so", "Static JNI")
            )
        ),
        CardData(
            title = "NATIVE · DYNAMIC",
            icon = "🔄",
            subtitle = "RegisterNatives via JNI_OnLoad — no exported symbols",
            checks = listOf(
                CheckItem("Su Binary Check", "Same logic, registered dynamically at runtime", "Dynamic JNI"),
                CheckItem("Magisk Mount", "/proc/mounts scan via RegisterNatives", "Dynamic JNI"),
                CheckItem("Frida Process", "/proc cmdline scan via RegisterNatives", "Dynamic JNI"),
                CheckItem("Frida Library", "/proc/self/maps scan via RegisterNatives", "Dynamic JNI")
            )
        ),
        CardData(
            title = "NATIVE · DLSYM",
            icon = "🔗",
            subtitle = "Hidden library loaded via dlsym() — obfuscated symbols",
            checks = listOf(
                CheckItem("Su Binary Check", "dlsym(handle, \"x7k9m\") → obfuscated function in libhidden_detector.so", "dlsym"),
                CheckItem("Magisk Mount", "dlsym(handle, \"p3q8r\") → obfuscated Magisk check", "dlsym"),
                CheckItem("Frida Detection", "dlsym(handle, \"w2e5t\") → obfuscated /proc/self/maps scan", "dlsym")
            )
        )
    )

    // ── onCreate ──────────────────────────────────────────────
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        rootingDetector = RootingDetector(this)

        cardsContainer = findViewById(R.id.cardsContainer)
        btnScanAll = findViewById(R.id.btnScanAll)
        txtSummary = findViewById(R.id.txtSummary)
        txtFooter = findViewById(R.id.txtFooter)

        buildUI()

        btnScanAll.setOnClickListener { runAllScans() }
    }

    // ── Build UI ──────────────────────────────────────────────
    private fun buildUI() {
        val cards = buildCards()
        cards.forEachIndexed { index, card ->
            val holder = createCardView(card, index)
            cardViews.add(holder)
            cardsContainer.addView(holder.root)
        }
    }

    @SuppressLint("SetTextI18n")
    private fun createCardView(card: CardData, index: Int): CardViewHolder {
        val dp = { v: Int -> dpToPx(v) }

        // ── Card Root ──
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundResource(R.drawable.bg_card)
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { bottomMargin = dp(8) }
            clipChildren = false
        }

        // ── Header ──
        val header = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(dp(16), dp(14), dp(16), dp(14))
        }

        // Icon
        val icon = TextView(this).apply {
            text = card.icon
            textSize = 18f
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { marginEnd = dp(12) }
        }

        // Title column
        val titleCol = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        }

        val title = monoText(card.title, 14f, colBright, bold = true)
        val subtitle = monoText(card.subtitle, 11f, colDim)

        titleCol.addView(title)
        titleCol.addView(subtitle)

        // Status badge
        val badge = TextView(this).apply {
            text = "  ──  "
            textSize = 11f
            typeface = Typeface.MONOSPACE
            setTextColor(colDim)
            setPadding(dp(8), dp(3), dp(8), dp(3))
        }

        // Expand arrow
        val arrow = monoText("▼", 12f, colDim)
        arrow.setPadding(dp(8), 0, 0, 0)

        header.addView(icon)
        header.addView(titleCol)
        header.addView(badge)
        header.addView(arrow)

        // ── Body (expandable) ──
        val body = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            visibility = View.GONE
            setPadding(dp(16), 0, dp(16), dp(12))
            setBackgroundColor(Color.parseColor("#0F1419"))
        }

        // Separator in body
        body.addView(View(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 1
            ).apply { bottomMargin = dp(10) }
            setBackgroundColor(colBorder)
        })

        // Check rows
        val checkRows = mutableListOf<CheckRowHolder>()
        card.checks.forEach { check ->
            val rowHolder = createCheckRow(check)
            checkRows.add(rowHolder)
            body.addView(rowHolder.row)
        }

        root.addView(header)
        root.addView(body)

        val holder = CardViewHolder(root, header, title, badge, arrow, body, checkRows)

        // Toggle expand on header click
        header.setOnClickListener { toggleCard(holder) }

        return holder
    }

    @SuppressLint("SetTextI18n")
    private fun createCheckRow(check: CheckItem): CheckRowHolder {
        val dp = { v: Int -> dpToPx(v) }

        val row = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(0, dp(6), 0, dp(6))
        }

        // Top row: indicator + name + result
        val topRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }

        val indicator = monoText("○", 10f, colDim)
        indicator.setPadding(0, 0, dp(8), 0)

        val name = monoText(check.name, 12f, colText)
        name.layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)

        val result = monoText("PENDING", 11f, colDim)

        topRow.addView(indicator)
        topRow.addView(name)
        topRow.addView(result)

        // Detail row
        val detail = monoText("  ↳ ${check.description}", 10f, colMuted)
        detail.setPadding(dp(18), dp(2), 0, 0)

        // Method badge
        val methodLine = monoText("  method: ${check.method}", 10f, colDim)
        methodLine.setPadding(dp(18), dp(1), 0, 0)

        row.addView(topRow)
        row.addView(detail)
        row.addView(methodLine)

        return CheckRowHolder(row, indicator, name, result, detail)
    }

    // ── Toggle Card Expand/Collapse ───────────────────────────
    private fun toggleCard(holder: CardViewHolder) {
        holder.expanded = !holder.expanded

        if (holder.expanded) {
            holder.bodyLayout.visibility = View.VISIBLE
            holder.bodyLayout.alpha = 0f
            holder.bodyLayout.animate().alpha(1f).setDuration(200).start()
            holder.arrowView.text = "▲"
            holder.arrowView.setTextColor(colGreen)
        } else {
            holder.bodyLayout.animate()
                .alpha(0f)
                .setDuration(150)
                .withEndAction { holder.bodyLayout.visibility = View.GONE }
                .start()
            holder.arrowView.text = "▼"
            holder.arrowView.setTextColor(colDim)
        }
    }

    // ── Run All Scans ─────────────────────────────────────────
    @SuppressLint("SetTextI18n")
    private fun runAllScans() {
        btnScanAll.isEnabled = false
        btnScanAll.text = "⟳  SCANNING..."
        btnScanAll.setTextColor(colAmber)
        txtFooter.text = "[ scanning... ]"
        txtFooter.setTextColor(colAmber)

        // Reset all indicators
        cardViews.forEach { card ->
            card.statusBadge.text = " ·· "
            card.statusBadge.setTextColor(colAmber)
            card.checkRows.forEach { row ->
                row.indicator.text = "○"
                row.indicator.setTextColor(colAmber)
                row.resultView.text = "..."
                row.resultView.setTextColor(colAmber)
            }
        }

        // Expand all cards
        cardViews.forEach { if (!it.expanded) toggleCard(it) }

        thread {
            val allResults = mutableListOf<Boolean>()
            val startTime = System.currentTimeMillis()

            // ── Card 0: Java Layer ──
            runCardChecks(0, listOf(
                { rootingDetector.checkRootingPackage() },
                { rootingDetector.checkSuBinary() }
            ), allResults)

            // ── Card 1: Native Static ──
            runCardChecks(1, listOf(
                { NativeDetector.checkSuExistsStatic() },
                { NativeDetector.checkMagiskMountStatic() },
                { NativeDetector.checkFridaProcessStatic() },
                { NativeDetector.checkFridaLibraryStatic() }
            ), allResults)

            // ── Card 2: Native Dynamic ──
            runCardChecks(2, listOf(
                { NativeDetector.checkSuExistsDynamic() },
                { NativeDetector.checkMagiskMountDynamic() },
                { NativeDetector.checkFridaProcessDynamic() },
                { NativeDetector.checkFridaLibraryDynamic() }
            ), allResults)

            // ── Card 3: Native Dlsym ──
            runCardChecks(3, listOf(
                { NativeDetector.checkSuExistsDlsym() },
                { NativeDetector.checkMagiskMountDlsym() },
                { NativeDetector.checkFridaDlsym() }
            ), allResults)

            val elapsed = System.currentTimeMillis() - startTime
            val detected = allResults.count { it }
            val total = allResults.size

            handler.post {
                btnScanAll.isEnabled = true
                btnScanAll.text = "▶  RUN ALL SCANS"
                btnScanAll.setTextColor(colGreen)

                txtSummary.text = "$detected/$total"
                txtSummary.setTextColor(if (detected > 0) colRed else colGreen)

                txtFooter.text = "[ scan complete · ${total} checks · ${elapsed}ms · $detected detected ]"
                txtFooter.setTextColor(if (detected > 0) colRed else colGreen)
            }
        }
    }

    @SuppressLint("SetTextI18n")
    private fun runCardChecks(
        cardIndex: Int,
        checks: List<() -> Boolean>,
        allResults: MutableList<Boolean>
    ) {
        val card = cardViews[cardIndex]
        val cardResults = mutableListOf<Boolean>()

        checks.forEachIndexed { i, checkFn ->
            val t0 = System.currentTimeMillis()
            val result = try {
                checkFn()
            } catch (e: Exception) {
                false
            }
            val elapsed = System.currentTimeMillis() - t0

            cardResults.add(result)
            allResults.add(result)

            handler.post {
                updateCheckRow(card.checkRows[i], result, elapsed)
            }

            // Stagger animation
            Thread.sleep(80)
        }

        // Update card badge
        val detected = cardResults.count { it }
        handler.post {
            if (detected > 0) {
                card.statusBadge.text = " $detected FOUND "
                card.statusBadge.setTextColor(colRed)
                card.statusBadge.setBackgroundColor(Color.parseColor("#33FF3333"))
                pulseView(card.statusBadge)
            } else {
                card.statusBadge.text = " CLEAN "
                card.statusBadge.setTextColor(colGreen)
                card.statusBadge.setBackgroundColor(Color.parseColor("#1A00FF41"))
            }
        }
    }

    @SuppressLint("SetTextI18n")
    private fun updateCheckRow(row: CheckRowHolder, detected: Boolean, timeMs: Long) {
        if (detected) {
            row.indicator.text = "●"
            row.indicator.setTextColor(colRed)
            row.resultView.text = "DETECTED ${timeMs}ms"
            row.resultView.setTextColor(colRed)
            row.nameView.setTextColor(colBright)
            pulseView(row.indicator)
        } else {
            row.indicator.text = "●"
            row.indicator.setTextColor(colGreen)
            row.resultView.text = "PASS ${timeMs}ms"
            row.resultView.setTextColor(colGreen)
            row.nameView.setTextColor(colText)
        }
    }

    // ── Pulse animation ───────────────────────────────────────
    private fun pulseView(view: View) {
        val anim = ValueAnimator.ofFloat(1f, 1.3f, 1f).apply {
            duration = 400
            interpolator = AccelerateDecelerateInterpolator()
            addUpdateListener {
                val scale = it.animatedValue as Float
                view.scaleX = scale
                view.scaleY = scale
            }
        }
        anim.start()
    }

    // ── Helpers ───────────────────────────────────────────────
    private fun monoText(text: String, sizeSp: Float, color: Int, bold: Boolean = false): TextView {
        return TextView(this).apply {
            this.text = text
            this.textSize = sizeSp
            typeface = if (bold) Typeface.create(Typeface.MONOSPACE, Typeface.BOLD) else Typeface.MONOSPACE
            setTextColor(color)
        }
    }

    private fun dpToPx(dp: Int): Int {
        return TypedValue.applyDimension(
            TypedValue.COMPLEX_UNIT_DIP,
            dp.toFloat(),
            resources.displayMetrics
        ).toInt()
    }
}
