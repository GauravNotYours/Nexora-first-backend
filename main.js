import "dotenv/config"
import fs from "node:fs"
import crypto from "node:crypto"
import express from "express"
import mongoose from "mongoose"
import bcrypt from "bcryptjs"
import jwt from "jsonwebtoken"
import cors from "cors"
import helmet from "helmet"
import rateLimit from "express-rate-limit"
import multer from "multer"

const app = express()
const port = Number(process.env.PORT || 3000)
const origins = (process.env.CLIENT_URL || "http://localhost:5173").split(",").map((value) => value.trim())
const jwtSecret = process.env.JWT_SECRET || "development-only-secret-change-me"
const domains = ["Water Resources", "Agriculture", "Healthcare", "Education", "Rural Livelihoods", "Environment & Mining", "Sanitation", "Energy & Solar", "Urban Infrastructure", "Accessibility"]
const statuses = ["Submitted", "Routed_HEI", "Proposal_Submitted", "In_Prototyping", "Industry_Sponsored", "Field_Testing", "Pilot_Deployed"]
const priorities = ["Critical", "High", "Medium", "Low"]
const roles = ["citizen", "university", "company", "admin"]

app.set("trust proxy", 1)
app.disable("x-powered-by")
app.use(helmet({ crossOriginResourcePolicy: { policy: "cross-origin" } }))
app.use(cors({ origin(origin, callback) { callback(null, !origin || origins.includes(origin)) } }))
app.use(express.json({ limit: "200kb" }))
app.use(rateLimit({ windowMs: 15 * 60 * 1000, limit: 300, standardHeaders: "draft-8", legacyHeaders: false }))

const locationSchema = new mongoose.Schema({ district: { type: String, required: true, trim: true, maxlength: 80 }, block: { type: String, required: true, trim: true, maxlength: 100 }, panchayatOrVillage: { type: String, required: true, trim: true, maxlength: 160 }, landmark: { type: String, trim: true, maxlength: 160 } }, { _id: false })
const evidenceSchema = new mongoose.Schema({ type: { type: String, enum: ["image", "document"], default: "image" }, caption: { type: String, maxlength: 300 }, fileSize: String, data: Buffer, contentType: String, url: String }, { _id: false })
const studentSchema = new mongoose.Schema({ id: String, name: String, rollNumber: String, discipline: String, semester: String, roleInProject: String }, { _id: false })
const proposalSchema = new mongoose.Schema({ id: String, universityName: String, universityShortName: String, departmentLead: String, facultyMentor: Object, studentMembers: [studentSchema], title: String, abstract: String, proposedBudgetINR: Number, estimatedTimelineMonths: Number, submissionDate: String, status: { type: String, enum: ["Draft", "Submitted", "Approved", "Under_Review"], default: "Submitted" } }, { _id: false })
const sponsorSchema = new mongoose.Schema({ id: String, companyName: String, companyType: String, contactPerson: String, csrFundAllocatedINR: Number, supportType: String, industryMentorsAssigned: [String], pledgeDate: String, deliverablesExpected: String, deploymentSite: String }, { _id: false })
const milestoneSchema = new mongoose.Schema({ id: String, title: String, description: String, dueDate: String, status: { type: String, enum: ["Pending", "In_Progress", "Completed", "Verified_By_Govt"], default: "Pending" }, completedDate: String, deliverableLink: String, evidenceNotes: String }, { _id: false })
const userSchema = new mongoose.Schema({ name: { type: String, required: true, trim: true, maxlength: 100 }, email: { type: String, required: true, unique: true, lowercase: true, trim: true, maxlength: 254 }, passwordHash: { type: String, required: true }, role: { type: String, enum: roles, required: true }, organization: { type: String, trim: true, maxlength: 160 }, bio: { type: String, trim: true, maxlength: 1000 } }, { timestamps: true })
const challengeSchema = new mongoose.Schema({ code: { type: String, required: true, unique: true, immutable: true }, title: { type: String, required: true, trim: true, maxlength: 180 }, description: { type: String, required: true, trim: true, maxlength: 5000 }, thematicDomain: { type: String, enum: domains, required: true }, location: { type: locationSchema, required: true }, submittedBy: { name: { type: String, required: true, trim: true, maxlength: 100 }, type: { type: String, enum: ["Citizen", "Panchayat", "SHG / NGO", "Government Dept", "Urban Local Body"], default: "Citizen" }, contactPhone: String, date: String }, evidence: [evidenceSchema], status: { type: String, enum: statuses, default: "Submitted" }, priority: { type: String, enum: priorities, default: "Medium" }, affectedPopulationEstimate: { type: Number, default: 0, min: 0 }, assignedUniversity: String, universityProposal: proposalSchema, industrySponsor: sponsorSchema, milestones: [milestoneSchema], socialImpactMetrics: { beneficiariesCount: Number, villagesCovered: Number, sdgGoal: String } }, { timestamps: true })

const User = mongoose.model("User", userSchema)
const Challenge = mongoose.model("Challenge", challengeSchema)
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 5 * 1024 * 1024, files: 4 }, fileFilter: (_req, file, callback) => callback(null, /^(image\/(jpeg|png|webp)|application\/pdf)$/.test(file.mimetype)) })
const clean = (value) => typeof value === "string" ? value.replace(/[<>]/g, "").trim() : value
const asyncRoute = (handler) => (req, res, next) => Promise.resolve(handler(req, res, next)).catch(next)
const makeCode = (domain) => "JHK-" + new Date().getFullYear() + "-" + (domain || "SOC").slice(0, 3).toUpperCase() + "-" + crypto.randomInt(100000, 1000000)
const publicChallenge = (challenge) => {
  const value = challenge.toObject ? challenge.toObject() : challenge
  const { aiClassification, upvotes, hasUserUpvoted, ...safe } = value
  const legacyStatus = safe.status === "AI_Validated" ? "Submitted" : safe.status
  return {
    ...safe,
    status: legacyStatus,
    id: String(value._id),
    evidence: (value.evidence || []).map((item, index) => ({
      type: item.type,
      url: item.data ? ("/api/challenges/" + value.code + "/evidence/" + index) : (item.url || "/api/challenges/" + value.code + "/evidence/" + index),
      caption: item.caption,
      fileSize: item.fileSize
    }))
  }
}
const tokenFor = (user) => jwt.sign({ sub: user.id, role: user.role }, jwtSecret, { expiresIn: "8h", issuer: "nexora-api", audience: "nexora-client" })
const authenticate = asyncRoute(async (req, res, next) => {
  const token = req.headers.authorization?.replace(/^Bearer\s+/i, "")
  if (!token) return res.status(401).json({ message: "Authentication required." })
  try {
    const payload = jwt.verify(token, jwtSecret, { issuer: "nexora-api", audience: "nexora-client" })
    req.user = await User.findById(payload.sub)
    if (!req.user) return res.status(401).json({ message: "Account no longer exists." })
    next()
  } catch { res.status(401).json({ message: "Your session has expired. Please sign in again." }) }
})
const allow = (...allowed) => (req, res, next) => allowed.includes(req.user.role) ? next() : res.status(403).json({ message: "You do not have permission for this action." })

app.get("/health", (_req, res) => res.json({ status: "ok", platform: "Nexora" }))
app.post("/api/auth/login", rateLimit({ windowMs: 15 * 60 * 1000, limit: 100 }), asyncRoute(async (req, res) => {
  const user = await User.findOne({ email: clean(req.body.email || "").toLowerCase() })
  if (!user || !(await bcrypt.compare(String(req.body.password || ""), user.passwordHash))) return res.status(401).json({ message: "Invalid email or password." })
  res.json({ token: tokenFor(user), user: { id: user.id, name: user.name, role: user.role, organization: user.organization, email: user.email } })
}))
app.post("/api/auth/admin-login", rateLimit({ windowMs: 15 * 60 * 1000, limit: 50 }), asyncRoute(async (req, res) => {
  const { email, password, accessKey } = req.body
  const expectedKey = process.env.ADMIN_ACCESS_KEY || "jharkhand-gov-console-2026"
  if (!accessKey || accessKey !== expectedKey) {
    return res.status(401).json({ message: "Invalid admin console access key." })
  }
  const user = await User.findOne({ email: clean(email || "").toLowerCase(), role: "admin" })
  if (!user || !(await bcrypt.compare(String(password || ""), user.passwordHash))) {
    return res.status(401).json({ message: "Invalid admin email or password." })
  }
  res.json({ token: tokenFor(user), user: { id: user.id, name: user.name, role: user.role, organization: user.organization, email: user.email } })
}))
app.post("/api/auth/register", asyncRoute(async (req, res) => {
  const { name, email, password, organization, role, bio } = req.body
  if (!["university", "company"].includes(role)) {
    return res.status(400).json({ message: "Role must be 'university' or 'company'." })
  }
  if (!clean(name || "") || !clean(email || "") || !String(password || "").trim()) {
    return res.status(400).json({ message: "Name, email, and password are required." })
  }
  if (String(password).length < 6) {
    return res.status(400).json({ message: "Password must be at least 6 characters." })
  }
  const existing = await User.findOne({ email: clean(email).toLowerCase() })
  if (existing) {
    return res.status(409).json({ message: "An account with this email already exists." })
  }
  const passwordHash = await bcrypt.hash(String(password), 10)
  const user = await User.create({
    name: clean(name),
    email: clean(email).toLowerCase(),
    passwordHash,
    role,
    organization: clean(organization || ""),
    bio: clean(bio || "")
  })
  res.status(201).json({
    token: tokenFor(user),
    user: { id: user.id, name: user.name, role: user.role, organization: user.organization, email: user.email }
  })
}))
app.get("/api/auth/me", authenticate, (req, res) => res.json({ id: req.user.id, name: req.user.name, role: req.user.role, organization: req.user.organization, email: req.user.email }))

app.get("/api/challenges", asyncRoute(async (req, res) => {
  const filter = {}
  if (req.query.district) filter["location.district"] = clean(req.query.district)
  if (req.query.domain) filter.thematicDomain = clean(req.query.domain)
  if (req.query.status) filter.status = clean(req.query.status)
  const items = await Challenge.find(filter).sort({ createdAt: -1 })
  res.json(items.map(publicChallenge))
}))
app.get("/api/challenges/:code", asyncRoute(async (req, res) => {
  const item = await Challenge.findOne({ code: req.params.code.toUpperCase() })
  if (!item) return res.status(404).json({ message: "Challenge not found." })
  res.json(publicChallenge(item))
}))
app.get("/api/challenges/:code/evidence/:index", asyncRoute(async (req, res) => {
  const item = await Challenge.findOne({ code: req.params.code.toUpperCase() })
  const evidence = item?.evidence[Number(req.params.index)]
  if (!evidence?.data) return res.sendStatus(404)
  res.type(evidence.contentType).send(evidence.data)
}))
app.post("/api/challenges", upload.array("evidence", 4), asyncRoute(async (req, res) => {
  const title = clean(req.body.title || ""), description = clean(req.body.description || ""), district = clean(req.body.district || ""), block = clean(req.body.block || ""), panchayatOrVillage = clean(req.body.panchayatOrVillage || "")
  const thematicDomain = clean(req.body.thematicDomain || "")
  if (!title || !description || !district || !block || !panchayatOrVillage) return res.status(400).json({ message: "Title, description, district, block, and village/ward are required." })
  if (!domains.includes(thematicDomain)) return res.status(400).json({ message: "Select a valid challenge domain." })
  let code
  do { code = makeCode(thematicDomain) } while (await Challenge.exists({ code }))
  const evidence = (req.files || []).map((file) => ({ type: file.mimetype === "application/pdf" ? "document" : "image", fileSize: Math.ceil(file.size / 1024) + " KB", data: file.buffer, contentType: file.mimetype }))
  const item = await Challenge.create({ code, title, description, thematicDomain, location: { district, block, panchayatOrVillage, landmark: clean(req.body.landmark || "") }, submittedBy: { name: clean(req.body.submitterName || "Community member"), type: "Citizen", contactPhone: clean(req.body.contactPhone || ""), date: new Date().toISOString().slice(0, 10) }, evidence, status: "Submitted", priority: "Medium", affectedPopulationEstimate: Number(req.body.affectedPopulationEstimate || 0), milestones: [] })
  res.status(201).json(publicChallenge(item))
}))
app.post("/api/challenges/:code/proposal", authenticate, allow("university", "admin"), asyncRoute(async (req, res) => {
  const proposal = { ...req.body, id: req.body.id || "prop-" + crypto.randomUUID(), submissionDate: new Date().toISOString().slice(0, 10), status: "Submitted" }
  if (!clean(proposal.title || "") || !clean(proposal.universityShortName || "")) return res.status(400).json({ message: "University name and proposal title are required." })
  const item = await Challenge.findOneAndUpdate({ code: req.params.code.toUpperCase() }, { universityProposal: proposal, assignedUniversity: proposal.universityShortName, status: "Proposal_Submitted" }, { new: true })
  if (!item) return res.status(404).json({ message: "Challenge not found." })
  res.json(publicChallenge(item))
}))
app.post("/api/challenges/:code/sponsorship", authenticate, allow("company", "admin"), asyncRoute(async (req, res) => {
  const sponsorship = { ...req.body, id: req.body.id || "csr-" + crypto.randomUUID(), pledgeDate: new Date().toISOString().slice(0, 10) }
  if (!clean(sponsorship.companyName || "") || !Number(sponsorship.csrFundAllocatedINR)) return res.status(400).json({ message: "Company name and CSR funding amount are required." })
  const item = await Challenge.findOneAndUpdate({ code: req.params.code.toUpperCase() }, { industrySponsor: sponsorship, status: "Industry_Sponsored" }, { new: true })
  if (!item) return res.status(404).json({ message: "Challenge not found." })
  res.json(publicChallenge(item))
}))
app.patch("/api/challenges/:code/milestones/:milestoneId", authenticate, allow("university", "admin"), asyncRoute(async (req, res) => {
  const item = await Challenge.findOne({ code: req.params.code.toUpperCase() })
  if (!item) return res.status(404).json({ message: "Challenge not found." })
  const milestone = item.milestones.find((value) => value.id === req.params.milestoneId)
  if (!milestone) return res.status(404).json({ message: "Milestone not found." })
  Object.assign(milestone, { status: clean(req.body.status || milestone.status), evidenceNotes: clean(req.body.evidenceNotes || milestone.evidenceNotes || ""), completedDate: req.body.status === "Completed" ? new Date().toISOString().slice(0, 10) : milestone.completedDate })
  if (item.milestones.length && item.milestones.every((value) => ["Completed", "Verified_By_Govt"].includes(value.status))) item.status = "Pilot_Deployed"
  await item.save()
  res.json(publicChallenge(item))
}))
app.patch("/api/admin/challenges/:code", authenticate, allow("admin"), asyncRoute(async (req, res) => {
  const update = {}
  if (statuses.includes(req.body.status)) update.status = req.body.status
  if (priorities.includes(req.body.priority)) update.priority = req.body.priority
  if (clean(req.body.assignedUniversity || "")) update.assignedUniversity = clean(req.body.assignedUniversity)
  const item = await Challenge.findOneAndUpdate({ code: req.params.code.toUpperCase() }, update, { new: true })
  if (!item) return res.status(404).json({ message: "Challenge not found." })
  res.json(publicChallenge(item))
}))
app.get("/api/admin/analytics", authenticate, allow("admin"), asyncRoute(async (_req, res) => {
  const [totalChallengesReceived, activeHEIProjects, pilotsDeployed, byDomain] = await Promise.all([Challenge.countDocuments(), Challenge.countDocuments({ status: { $in: ["Proposal_Submitted", "In_Prototyping", "Industry_Sponsored", "Field_Testing"] } }), Challenge.countDocuments({ status: "Pilot_Deployed" }), Challenge.aggregate([{ $group: { _id: "$thematicDomain", count: { $sum: 1 } } }])])
  res.json({ totalChallengesReceived, activeHEIProjects, pilotsDeployed, byDomain })
}))
app.post("/api/admin/users", authenticate, allow("admin"), asyncRoute(async (req, res) => {
  const { name, email, password, role, organization, bio } = req.body
  if (!["university", "company"].includes(role) || !clean(name || "") || !clean(email || "") || String(password || "").length < 12) return res.status(400).json({ message: "Provide name, email, university/company role, and a password of at least 12 characters." })
  const user = await User.create({ name: clean(name), email: clean(email).toLowerCase(), passwordHash: await bcrypt.hash(password, 12), role, organization: clean(organization || ""), bio: clean(bio || "") })
  res.status(201).json({ id: user.id, name: user.name, role: user.role, organization: user.organization, email: user.email })
}))

async function ensureSeedData() {
  const { ADMIN_EMAIL = "admin@example.com", ADMIN_PASSWORD = "replace-with-a-strong-password-at-least-12-characters", ADMIN_NAME = "Nexora Administrator" } = process.env
  if (!(await User.exists({ email: ADMIN_EMAIL.toLowerCase() }))) {
    await User.create({ name: ADMIN_NAME, email: ADMIN_EMAIL.toLowerCase(), passwordHash: await bcrypt.hash(ADMIN_PASSWORD, 10), role: "admin", organization: "Department of Higher & Technical Education" })
  }
  const demoAccounts = [
    {
      name: "Dr. Sanjay Sinha",
      email: "university@bitmesra.ac.in",
      password: "University@1234",
      role: "university",
      organization: "BIT Mesra",
      bio: "Department of Mechanical & Mechatronics, BIT Mesra."
    },
    {
      name: "Siddharth Mukherjee",
      email: "csr@tatasteel.com",
      password: "Industry@1234",
      role: "company",
      organization: "Tata Steel Foundation",
      bio: "Head of Rural Water Initiatives & CSR, Tata Steel Foundation."
    }
  ]
  for (const account of demoAccounts) {
    await User.findOneAndUpdate({ email: account.email }, {
      $setOnInsert: {
        name: account.name,
        email: account.email,
        role: account.role,
        organization: account.organization,
        bio: account.bio
      },
      $set: { passwordHash: await bcrypt.hash(account.password, 10) }
    }, { upsert: true, setDefaultsOnInsert: true })
  }
  const count = await Challenge.countDocuments()
  if (count === 0 && fs.existsSync(new URL("./cleanChallenges.json", import.meta.url))) {
    const raw = fs.readFileSync(new URL("./cleanChallenges.json", import.meta.url), "utf8")
    const challenges = JSON.parse(raw)
    await Challenge.insertMany(challenges)
    console.log(`Seeded ${challenges.length} real challenges into MongoDB.`)
  }
}
app.use((error, _req, res, _next) => {
  if (error instanceof multer.MulterError || error.message?.includes("image")) return res.status(400).json({ message: "Upload up to four JPG, PNG, WebP, or PDF evidence files under 5 MB each." })
  if (error.name === "ValidationError") return res.status(400).json({ message: error.message })
  console.error(error)
  res.status(500).json({ message: "Something went wrong. Please try again." })
})
mongoose.connect(process.env.MONGODB_URI || "mongodb://127.0.0.1:27017/nexora").then(async () => { await ensureSeedData(); app.listen(port, () => console.log("Nexora API listening on " + port)) }).catch((error) => { console.error("MongoDB connection failed:", error.message); process.exit(1) })
