// server.js
const express = require("express");
const cors = require("cors");
require("dotenv").config();
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const PDFDocument = require("pdfkit");
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);

// Firebase Admin init
const decoded = Buffer.from(process.env.FB_SERVICE_KEY, "base64").toString(
  "utf-8"
);
const admin = require("firebase-admin");
const serviceAccount = JSON.parse(decoded);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const app = express();

app.use(express.json());
app.use(
  cors({
    origin: ["http://localhost:5173", "https://civil-report.vercel.app"],
    credentials: true,
  })
);

// JWT Middleware

const verifyJWT = async (req, res, next) => {
  const auth = req.headers.authorization;
  if (!auth?.startsWith("Bearer ")) {
    return res.status(401).send({ message: "Unauthorized Access!" });
  }
  const token = auth.split(" ")[1];

  try {
    const decoded = await admin.auth().verifyIdToken(token);
    req.tokenEmail = decoded.email;
    next();
  } catch (err) {
    return res.status(401).send({ message: "Unauthorized Token!" });
  }
};

const PORT = process.env.PORT || 5000;
const MONGO_URI = process.env.MONGO_URI;

const client = new MongoClient(MONGO_URI, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
  },
});

async function run() {
  try {
    const db = client.db("civil-report");
    const usersCollection = db.collection("users");
    const issuesCollection = db.collection("issues");
    const paymentsCollection = db.collection("payments");
    const timelineCollection = db.collection("timeline");

    const verifyAdmin = async (req, res, next) => {
      const email = req.tokenEmail;
      const user = await usersCollection.findOne({ email });
      if (user?.role !== "admin")
        return res
          .status(403)
          .send({ message: "Admin only Actions!", role: user?.role });

      next();
    };

    const verifyBlockedUser = async (req, res, next) => {
      const email = req.tokenEmail;
      const user = await usersCollection.findOne({ email });

      if (user?.isBlocked) {
        return res.status(403).send({
          error: true,
          message: "Your account is blocked. You cannot perform this action.",
        });
      }
      next();
    };

    // USER SECTION

    // Login/Register upsert
    app.post("/user", async (req, res) => {
      const userData = req.body;
      const email = userData.email;
      const now = new Date().toISOString();

      const update = {
        $set: {
          name: userData.name,
          email: email,
          image: userData.image,
          last_loggedIn: now,
        },
        $setOnInsert: {
          role: "citizen",
          created_at: now,
        },
      };

      const result = await usersCollection.updateOne({ email }, update, {
        upsert: true,
      });

      res.send(result);
    });

    // Get user role
    app.get("/user/role", verifyJWT, async (req, res) => {
      const email = req.tokenEmail;
      const user = await usersCollection.findOne({ email });
      res.send({ role: user?.role || "citizen" });
    });

    // Get all users (Admin)
    app.get("/users", verifyJWT, verifyAdmin, async (req, res) => {
      const users = await usersCollection.find().toArray();
      res.send(users);
    });

    app.patch("/users/:id", verifyJWT, verifyAdmin, async (req, res) => {
      const id = req.params.id;
      const { isBlocked } = req.body;

      const result = await usersCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: { isBlocked } }
      );

      res.send({
        success: true,
        message: `User is now ${isBlocked ? "Blocked" : "Unblocked"}`,
      });
    });

    // STAFF SECTION

    app.post(
      "/admin/create-staff",
      verifyJWT,
      verifyAdmin,
      async (req, res) => {
        const staff = req.body;
        if (!staff.email || !staff.name)
          return res.status(400).send({ error: "name & email required" });

        const now = new Date().toISOString();

        const doc = {
          name: staff.name,
          email: staff.email,
          phone: staff.phone || "",
          role: "staff",
          created_at: now,
        };

        const result = await usersCollection.updateOne(
          { email: staff.email },
          { $set: doc },
          { upsert: true }
        );

        res.send({ success: true, result });
      }
    );

    app.get("/admin/staff", verifyJWT, verifyAdmin, async (req, res) => {
      const staff = await usersCollection.find({ role: "staff" }).toArray();
      res.send(staff);
    });

    app.patch("/admin/staff/:id", verifyJWT, verifyAdmin, async (req, res) => {
      const id = req.params.id;
      const update = req.body;
      const result = await usersCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: update }
      );
      res.send(result);
    });

    app.delete("/admin/staff/:id", verifyJWT, verifyAdmin, async (req, res) => {
      const id = req.params.id;
      const result = await usersCollection.deleteOne({ _id: new ObjectId(id) });
      res.send(result);
    });

    app.get("/staff/today-tasks", verifyJWT, async (req, res) => {
      const email = req.tokenEmail;
      const staff = await usersCollection.findOne({ email });
      if (!staff) return res.status(404).send({ message: "Staff not found" });

      const today = new Date();
      today.setHours(0, 0, 0, 0); // start of today

      const tasks = await issuesCollection
        .find({
          "assignedTo._id": staff._id.toString(),
          createdAt: { $gte: today }, // tasks created today
        })
        .sort({ createdAt: -1 })
        .toArray();

      res.send(tasks);
    });

    // Firebase
    app.post(
      "/admin/create-staff",
      verifyJWT,
      verifyAdmin,
      async (req, res) => {
        const { name, email, phone, password } = req.body;

        if (!name || !email || !password) {
          return res
            .status(400)
            .send({ error: "Name, email & password required" });
        }

        try {
          // 1. Create user in Firebase Auth
          const firebaseUser = await admin.auth().createUser({
            email,
            password,
            displayName: name,
          });

          // 2. Add user to MongoDB
          const now = new Date().toISOString();
          const doc = {
            _id: firebaseUser.uid,
            name,
            email,
            phone: phone || "",
            role: "staff",
            created_at: now,
          };

          await usersCollection.updateOne(
            { email },
            { $set: doc },
            { upsert: true }
          );

          res.send({ success: true, firebaseUser });
        } catch (error) {
          console.error(error);
          res.status(500).send({ error: error.code || error.message });
        }
      }
    );

    // ISSUES

    app.post("/issues", verifyJWT, verifyBlockedUser, async (req, res) => {
      try {
        const data = req.body;
        const email = req.tokenEmail;

        const user = await usersCollection.findOne({ email });
        if (!user) {
          return res
            .status(403)
            .send({ error: true, message: "User not found" });
        }

        // Free user limit
        if (user.role === "citizen" && !user.premium) {
          const count = await issuesCollection.countDocuments({ email });
          if (count > 3) {
            return res
              .status(403)
              .send({ error: true, message: "Free user limit reached!" });
          }
        }

        data.status = "pending";
        data.priority = data.priority || "normal";
        data.email = email;
        data.createdAt = new Date();

        const result = await issuesCollection.insertOne(data);

        await timelineCollection.insertOne({
          issueId: result.insertedId.toString(),
          message: "Issue Created",
          time: new Date(),
        });

        res.send({ success: true, data: result });
      } catch (error) {
        res.status(500).send({ error: true, message: error.message });
      }
    });

    app.get("/all-issues", async (req, res) => {
      try {
        const {
          page = 1,
          limit = 10,
          status,
          priority,
          category,
          search,
        } = req.query;
        const query = {};

        if (status) query.status = status;
        if (priority) query.priority = priority;
        if (category) query.category = category;
        if (search) query.title = { $regex: search, $options: "i" };

        const skip = (parseInt(page) - 1) * parseInt(limit);
        const total = await issuesCollection.countDocuments(query);

        const issues = await issuesCollection
          .find(query)
          .sort({ priority: -1, createdAt: -1 })
          .skip(skip)
          .limit(parseInt(limit))
          .toArray();

        res.send({
          total,
          page: parseInt(page),
          limit: parseInt(limit),
          issues,
        });
      } catch (err) {
        res.status(500).send({ error: err.message });
      }
    });

    app.get("/issues", verifyJWT, async (req, res) => {
      const email = req.query.email || req.tokenEmail;
      const user = await usersCollection.findOne({ email });

      let query = {};
      if (user.role === "staff") {
        query = { "assignedTo.email": email };
      } else if (user.role === "citizen") query = { email: user.email };

      const issues = await issuesCollection.find(query).toArray();
      res.send(issues);
    });

    app.get("/issues/:id", verifyJWT, async (req, res) => {
      try {
        const id = req.params.id;
        const issue = await issuesCollection.findOne({
          _id: new ObjectId(id),
        });

        if (!issue) {
          return res.status(404).send({ error: "Issue not found" });
        }

        res.send(issue);
      } catch (err) {
        res.status(500).send({ error: err.message });
      }
    });

    // Assign issue or update issue
    app.patch("/issues/:id", verifyJWT, verifyBlockedUser, async (req, res) => {
      const id = req.params.id;
      const { status, assignedTo } = req.body;
      const email = req.tokenEmail;

      const issue = await issuesCollection.findOne({ _id: new ObjectId(id) });
      if (!issue) return res.status(404).send({ error: "Issue not found" });

      // allow update only if assigned staff or admin
      const user = await usersCollection.findOne({ email });
      const isAdmin = user.role === "admin";
      const isAssignedStaff =
        user.role === "staff" &&
        (issue.assignedTo?.email === email || !issue.assignedTo);

      if (!isAdmin && !isAssignedStaff) {
        return res.status(403).send({ error: "Not allowed" });
      }

      // Build update object dynamically
      const updateObj = {};
      if (status) updateObj.status = status;
      if (assignedTo) updateObj.assignedTo = assignedTo;

      const result = await issuesCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: updateObj }
      );

      // Add timeline entry if assigned
      if (assignedTo) {
        await timelineCollection.insertOne({
          issueId: id,
          message: `Issue assigned to ${assignedTo.name}`,
          updatedBy: user.name,
          time: new Date(),
        });
      }

      res.send({ success: true, result });
    });

    app.post(
      "/issues/:id/upvote",
      verifyJWT,
      verifyBlockedUser,
      async (req, res) => {
        try {
          const id = req.params.id;
          const email = req.tokenEmail;

          const issue = await issuesCollection.findOne({
            _id: new ObjectId(id),
          });
          if (!issue) return res.status(404).send({ error: "Issue not found" });

          if (issue.email === email)
            return res.status(403).send({ error: "Cannot upvote own issue" });

          const hasUpvoted = issue.upvotes?.includes(email);
          if (hasUpvoted)
            return res.status(403).send({ error: "Already upvoted" });

          const result = await issuesCollection.updateOne(
            { _id: new ObjectId(id) },
            { $push: { upvotes: email }, $inc: { upvoteCount: 1 } }
          );

          await timelineCollection.insertOne({
            issueId: id,
            message: `Upvoted by ${email}`,
            updatedBy: email,
            status: issue.status,
            time: new Date(),
          });

          res.send({
            success: true,
            message: "Upvoted",
            upvoteCount: (issue.upvoteCount || 0) + 1,
          });
        } catch (err) {
          res.status(500).send({ error: err.message });
        }
      }
    );

    app.post(
      "/issues/:id/boost",
      verifyJWT,
      verifyBlockedUser,
      async (req, res) => {
        try {
          const id = req.params.id;
          const email = req.tokenEmail;
          const issue = await issuesCollection.findOne({
            _id: new ObjectId(id),
          });

          if (!issue) return res.status(404).send({ error: "Issue not found" });
          if (issue.priority === "high")
            return res.status(400).send({ error: "Already boosted" });

          // Assume payment is done via front-end and passed as object
          const payment = {
            email,
            amount: 100,
            type: "boost",
            issueId: id,
            createdAt: new Date(),
          };
          await paymentsCollection.insertOne(payment);

          await issuesCollection.updateOne(
            { _id: new ObjectId(id) },
            { $set: { priority: "high" } }
          );

          await timelineCollection.insertOne({
            issueId: id,
            message: `Issue boosted by ${email}`,
            updatedBy: email,
            status: issue.status,
            time: new Date(),
          });

          res.send({ success: true, message: "Issue boosted successfully" });
        } catch (err) {
          res.status(500).send({ error: err.message });
        }
      }
    );

    //  ISSUE TIMELINE
    app.get("/issues/:id/timeline", verifyJWT, async (req, res) => {
      try {
        const id = req.params.id;
        const timeline = await timelineCollection
          .find({ issueId: id })
          .sort({ time: -1 })
          .toArray();
        res.send(timeline);
      } catch (err) {
        res.status(500).send({ error: err.message });
      }
    });

    //  EDIT ISSUE (Citizen)
    app.patch(
      "/issues/:id/edit",
      verifyJWT,
      verifyBlockedUser,
      async (req, res) => {
        try {
          const id = req.params.id;
          const email = req.tokenEmail;
          const data = req.body;

          const issue = await issuesCollection.findOne({
            _id: new ObjectId(id),
          });
          if (!issue) return res.status(404).send({ error: "Issue not found" });
          if (issue.email !== email)
            return res.status(403).send({ error: "Not allowed" });
          if (issue.status !== "pending")
            return res.status(400).send({ error: "Cannot edit this issue" });

          await issuesCollection.updateOne(
            { _id: new ObjectId(id) },
            { $set: data }
          );

          await timelineCollection.insertOne({
            issueId: id,
            message: "Issue edited",
            updatedBy: email,
            status: issue.status,
            time: new Date(),
          });

          res.send({ success: true, message: "Issue updated" });
        } catch (err) {
          res.status(500).send({ error: err.message });
        }
      }
    );

    //  DELETE ISSUE (Citizen)
    app.delete(
      "/issues/:id/delete",
      verifyJWT,
      verifyBlockedUser,
      async (req, res) => {
        try {
          const id = req.params.id;
          const email = req.tokenEmail;

          const issue = await issuesCollection.findOne({
            _id: new ObjectId(id),
          });
          if (!issue) return res.status(404).send({ error: "Issue not found" });
          if (issue.email !== email)
            return res.status(403).send({ error: "Not allowed" });
          if (issue.status !== "pending")
            return res.status(400).send({ error: "Cannot delete this issue" });

          await issuesCollection.deleteOne({ _id: new ObjectId(id) });
          await timelineCollection.insertOne({
            issueId: id,
            message: "Issue deleted",
            updatedBy: email,
            status: "deleted",
            time: new Date(),
          });

          res.send({ success: true, message: "Issue deleted" });
        } catch (err) {
          res.status(500).send({ error: err.message });
        }
      }
    );

    //  REJECT ISSUE (ADMIN)
    app.patch(
      "/issues/:id/reject",
      verifyJWT,
      verifyAdmin,
      async (req, res) => {
        try {
          const id = req.params.id;
          const issue = await issuesCollection.findOne({
            _id: new ObjectId(id),
          });
          if (!issue) return res.status(404).send({ error: "Issue not found" });
          if (issue.status !== "pending")
            return res
              .status(400)
              .send({ error: "Only pending issues can be rejected" });

          await issuesCollection.updateOne(
            { _id: new ObjectId(id) },
            { $set: { status: "rejected" } }
          );

          await timelineCollection.insertOne({
            issueId: id,
            message: "Issue rejected",
            updatedBy: req.tokenEmail,
            status: "rejected",
            time: new Date(),
          });

          res.send({ success: true, message: "Issue rejected" });
        } catch (err) {
          res.status(500).send({ error: err.message });
        }
      }
    );

    // Latest resolved issues
    app.get("/issues/resolved/latest", async (req, res) => {
      try {
        const issues = await issuesCollection
          .find({ status: "resolved" })
          .sort({ updatedAt: -1, createdAt: -1 })
          .limit(6)
          .toArray();

        res.send(issues);
      } catch (err) {
        res.status(500).send({ error: err.message });
      }
    });

    // PAYMENT

    app.post("/payment", verifyJWT, async (req, res) => {
      const payload = req.body;
      payload.email = req.tokenEmail;
      payload.createdAt = new Date();

      const result = await paymentsCollection.insertOne(payload);
      res.send(result);
    });

    app.get("/payment", verifyJWT, verifyAdmin, async (req, res) => {
      const list = await paymentsCollection.find().toArray();
      res.send(list);
    });

    app.get("/user/info/:email", verifyJWT, async (req, res) => {
      const email = req.params.email;
      const user = await usersCollection.findOne({ email });
      res.send({
        role: user.role,
        premium: user.premium || false,
        blocked: user.isBlocked || false,
      });
    });

    // Create Stripe Checkout Session
    app.post(
      "/create-checkout-session",
      verifyJWT,
      verifyBlockedUser,
      async (req, res) => {
        try {
          const email = req.tokenEmail;
          const session = await stripe.checkout.sessions.create({
            payment_method_types: ["card"],
            line_items: [
              {
                price_data: {
                  currency: "bdt",
                  product_data: {
                    name: "Premium Subscription",
                    description: "Unlimited issue submission access",
                  },
                  unit_amount: 1000 * 100,
                },
                quantity: 1,
              },
            ],
            mode: "payment",
            customer_email: email,
            metadata: {
              type: "premium-subscription",
              email,
            },
            success_url: `${process.env.CLIENT_DOMAIN}/payment-success?session_id={CHECKOUT_SESSION_ID}`,
            cancel_url: `${process.env.CLIENT_DOMAIN}/profile?success=false`,
          });

          res.send({ url: session.url });
        } catch (error) {
          console.error("Checkout Error:", error);
          res.status(500).send({ error: error.message });
        }
      }
    );

    // app.post("/session-status", verifyJWT, async (req, res) => {
    //   try {
    //     const { sessionId } = req.body;
    //     const userEmail = req.tokenEmail;

    //     const user = await usersCollection.findOne({ email: userEmail });
    //     if (user?.isBlocked) {
    //       return res
    //         .status(403)
    //         .send({ error: "User is blocked. Payment not allowed." });
    //     }

    //     // Retrieve Stripe session
    //     const session = await stripe.checkout.sessions.retrieve(sessionId);

    //     if (session.payment_status !== "paid") {
    //       return res.send({ success: false, boosted: false });
    //     }

    //     const metadata = session.metadata;

    //     // Handle issue boost
    //     if (metadata.type === "issue-boost") {
    //       const issueId = metadata.issueId;
    //       const email = metadata.email;

    //       // Update issue priority
    //       await issuesCollection.updateOne(
    //         { _id: new ObjectId(issueId) },
    //         { $set: { priority: "high" } }
    //       );

    //       // Add timeline entry
    //       await timelineCollection.insertOne({
    //         issueId,
    //         message: "Issue boosted via payment",
    //         updatedBy: email,
    //         status: "boosted",
    //         time: new Date(),
    //       });

    //       // Record payment
    //       await paymentsCollection.insertOne({
    //         email,
    //         transactionId: session.payment_intent,
    //         amount: session.amount_total / 100,
    //         type: "boost",
    //         issueId,
    //         status: "complete",
    //         date: new Date(),
    //       });

    //       return res.send({ success: true, boosted: true, issueId });
    //     }

    //     // Handle subscription (if needed)
    //     if (metadata.type === "premium-subscription") {
    //       const transactionId = session.payment_intent;
    //       const existPayment = await paymentsCollection.findOne({
    //         transactionId,
    //       });

    //       if (!existPayment) {
    //         await paymentsCollection.insertOne({
    //           email: metadata.email,
    //           transactionId,
    //           amount: session.amount_total / 100,
    //           type: "subscription",
    //           status: "complete",
    //           date: new Date(),
    //         });

    //         await usersCollection.updateOne(
    //           { email: metadata.email },
    //           { $set: { premium: true } }
    //         );
    //       }

    //       return res.send({ success: true, premium: true });
    //     }

    //     res.send({ success: false });
    //   } catch (err) {
    //     console.error("Session Status Error:", err);
    //     res.status(500).send({ error: err.message });
    //   }
    // });

    // Boost Payment

    app.post("/session-status", verifyJWT, async (req, res) => {
      try {
        const { sessionId } = req.body;
        const userEmail = req.tokenEmail;
        if (!sessionId) {
          return res
            .status(400)
            .send({ success: false, message: "Session ID required" });
        }

        // Retrieve Stripe session
        const session = await stripe.checkout.sessions.retrieve(sessionId);

        // Check if payment is complete
        if (session.payment_status !== "paid") {
          return res.send({ success: false, message: "Payment not completed" });
        }

        const { type, email, issueId } = session.metadata;

        if (type === "issue-boost") {
          await issuesCollection.updateOne(
            { _id: new ObjectId(issueId) },
            { $set: { priority: "high" } }
          );

          await timelineCollection.insertOne({
            issueId,
            message: "Issue boosted via payment",
            updatedBy: email,
            status: "boosted",
            time: new Date(),
          });

          await paymentsCollection.insertOne({
            email: userEmail,
            transactionId: session.payment_intent,
            amount: session.amount_total / 100,
            type: "boost",
            issueId,
            status: "complete",
            date: new Date(),
          });

          return res.send({ success: true, boosted: true });
        }

        if (type === "premium-subscription") {
          const transactionId = session.payment_intent;

          // Avoid duplicate payment entry
          const existPayment = await paymentsCollection.findOne({
            transactionId,
          });

          if (!existPayment) {
            // Insert payment record
            await paymentsCollection.insertOne({
              email,
              transactionId,
              amount: session.amount_total / 100,
              type: "subscription",
              status: "complete",
              date: new Date(),
            });

            // Update user premium status
            await usersCollection.updateOne(
              { email: userEmail },
              { $set: { premium: true } }
            );
          }

          return res.send({ success: true, premium: true });
        }

        // Default response if type not recognized
        res.send({ success: false, message: "Invalid payment type" });
      } catch (err) {
        console.error("Session Status Error:", err);
        res.status(500).send({ error: err.message });
      }
    });

    // Boost payment
    app.post(
      "/issues/:id/boost-checkout",
      verifyJWT,
      verifyBlockedUser,
      async (req, res) => {
        try {
          const { id } = req.params;
          const email = req.tokenEmail;

          // Find the issue
          const issue = await issuesCollection.findOne({
            _id: new ObjectId(id),
          });
          if (!issue) return res.status(404).send({ error: "Issue not found" });
          if (issue.priority === "high")
            return res.status(400).send({ error: "Issue already boosted" });

          // Create Stripe Checkout Session
          const session = await stripe.checkout.sessions.create({
            payment_method_types: ["card"],
            line_items: [
              {
                price_data: {
                  currency: "bdt",
                  product_data: {
                    name: "Issue Boost",
                    description: `Boost issue: ${issue.title}`,
                  },
                  unit_amount: 100 * 100, // 100 BDT
                },
                quantity: 1,
              },
            ],
            mode: "payment",
            customer_email: email,
            metadata: {
              type: "issue-boost",
              issueId: id,
              email, // important for timeline
            },
            success_url: `${process.env.CLIENT_DOMAIN}/boost-success?session_id={CHECKOUT_SESSION_ID}`,
            cancel_url: `${process.env.CLIENT_DOMAIN}/issue/${id}`,
          });

          res.send({ url: session.url });
        } catch (err) {
          console.error("Boost Checkout Error:", err);
          res.status(500).send({ error: err.message });
        }
      }
    );

    // Citizen STATS

    app.get("/citizen/stats", verifyJWT, async (req, res) => {
      try {
        const email = req.tokenEmail;

        // Helper function to count issues with case-insensitive status match
        const countByStatus = async (status) => {
          return await issuesCollection.countDocuments({
            email,
            status: { $regex: `^${status}$`, $options: "i" }, // case-insensitive exact match
          });
        };

        const totalIssues = await issuesCollection.countDocuments({ email });
        const pending = await countByStatus("pending");
        const inProgress = await countByStatus("in-progress");
        const resolved = await countByStatus("resolved");

        const totalPayments = await paymentsCollection.countDocuments({
          email,
        });

        // Optional: fetch latest 5 issues
        const latestIssues = await issuesCollection
          .find({ email })
          .sort({ createdAt: -1 })
          .limit(5)
          .toArray();

        res.send({
          totalIssues,
          pending,
          inProgress,
          resolved,
          totalPayments,
          latestIssues,
        });
      } catch (err) {
        console.error(err);
        res.status(500).send({ error: "Failed to fetch dashboard stats" });
      }
    });

    // STAFF DASHBOARD STATS
    app.get("/staff/stats", verifyJWT, async (req, res) => {
      const email = req.tokenEmail;

      // find staff user
      const staff = await usersCollection.findOne({ email });
      if (!staff) {
        return res.status(404).send({ message: "User not found" });
      }

      // find issues assigned to this staff
      const myIssues = await issuesCollection
        .find({ "assignedTo._id": staff._id.toString() })
        .sort({ createdAt: -1 })
        .toArray();

      const stats = {
        assigned: myIssues.length,
        resolved: myIssues.filter(
          (i) => i.status === "resolved" || i.status === "closed"
        ).length,
        active: myIssues.filter((i) => i.status === "in-progress").length,
        recent: myIssues.slice(0, 5),
      };

      res.send(stats);
    });

    // ADMIN STATS
    app.get("/admin/stats", verifyJWT, verifyAdmin, async (req, res) => {
      const totalIssues = await issuesCollection.countDocuments();
      const resolved = await issuesCollection.countDocuments({
        status: "resolved",
      });
      const pending = await issuesCollection.countDocuments({
        status: "pending",
      });
      const totalPayments = await paymentsCollection.countDocuments();
      const latestIssues = await issuesCollection
        .find()
        .sort({ createdAt: -1 })
        .limit(5)
        .toArray();
      const latestPayments = await paymentsCollection
        .find()
        .sort({ createdAt: -1 })
        .limit(5)
        .toArray();
      const latestUsers = await usersCollection
        .find()
        .sort({ created_at: -1 })
        .limit(5)
        .toArray();

      res.send({
        totalIssues,
        resolved,
        pending,
        totalPayments,
        latestIssues,
        latestPayments,
        latestUsers,
      });
    });

    // Download invoice by payment ID

    //
    app.get("/payment/:id/invoice", verifyJWT, async (req, res) => {
      try {
        const { id } = req.params;

        // Validate MongoDB ObjectId
        if (!id.match(/^[0-9a-fA-F]{24}$/)) {
          return res.status(400).send({ error: "Invalid Payment ID" });
        }

        const payment = await paymentsCollection.findOne({
          _id: new ObjectId(id),
        });

        if (!payment) {
          return res.status(404).send({ error: "Payment not found" });
        }

        // Create PDF
        const PDFDocument = require("pdfkit");
        const doc = new PDFDocument();

        // Set response headers
        res.setHeader("Content-Type", "application/pdf");
        res.setHeader(
          "Content-Disposition",
          `attachment; filename=invoice_${id}.pdf`
        );

        // Pipe PDF to response
        doc.pipe(res);

        // Add invoice content
        doc.fontSize(20).text("Invoice", { align: "center" });
        doc.moveDown();
        doc.fontSize(14).text(`Payment ID: ${payment._id.toString()}`);
        doc.text(`Email: ${payment.email || "N/A"}`);
        doc.text(`Amount: ${payment.amount != null ? payment.amount : 0} tk`);
        doc.text(`Type: ${payment.type || "N/A"}`);
        doc.text(`Status: ${payment.status || "complete"}`);
        doc.text(
          `Date: ${
            payment.date ? new Date(payment.date).toLocaleString() : "N/A"
          }`
        );

        doc.end(); // Finalize PDF
      } catch (err) {
        console.error("Invoice generation error:", err);
        res.status(500).send({ error: "Failed to generate invoice" });
      }
    });

    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!"
    );
  } finally {
  }
}

run().catch((err) => console.error(err));

app.get("/", (req, res) => res.send("Public Report API Running..."));

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

module.exports = app;
