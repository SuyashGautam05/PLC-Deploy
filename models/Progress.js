const mongoose = require('mongoose');

// One document per (user, topic) pair. Re-reading a topic just bumps
// lastReadAt / readCount instead of creating a duplicate row.
const progressSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    appId: { type: String, default: 'plc-simtel' },

    // topicId is the unique key for a topic - we use the link's href
    // (e.g. "./pages/.../Definition_and_Scope_of_Industrial_Automation.html")
    // since it's already unique per topic across the whole menu.
    topicId: { type: String, required: true },
    topicTitle: { type: String, default: '' },
    topicUrl: { type: String, default: '' },
    sectionTitle: { type: String, default: '' },

    firstReadAt: { type: Date, default: Date.now },
    lastReadAt: { type: Date, default: Date.now },
    readCount: { type: Number, default: 1 }
}, { timestamps: true });

progressSchema.index({ user: 1, topicId: 1 }, { unique: true });

module.exports = mongoose.models.Progress || mongoose.model('Progress', progressSchema);